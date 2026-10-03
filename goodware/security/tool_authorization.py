"""
Goodware v3.0 — Tool Authorization Layer.

Wraps LLM tool calls with the Constitutional Guard + OOB/multi-party
gate. This is the enforcement of Section 2.1 of the audit:  "Ações
   destrutivas exigem OOB ou multi-party".

The high-level call site (brain.py) MUST route every destructive
tool through authorize_tool_call(). Read-only and informational
tools may pass through with a single APPROVE verdict.
"""
from __future__ import annotations

import functools
import logging
import time
from typing import Any, Callable, Dict, Optional

from .constitutional_guard import (
    ConstitutionalGuard,
    DESTRUCTIVE_ACTIONS,
    GuardVerdict,
    InvariantViolation,
)

log = logging.getLogger("goodware.security.tool_auth")


# Tools that are read-only or informational — they pass through without OOB
READ_ONLY_TOOLS = {
    "search_iocs", "search_cves", "run_yara_scan",
    "generate_pqc_keypair", "sign_pqc", "verify_pqc",
    "alert_human", "no_action", "request_oob_approval",
    "list_snapshots", "get_status", "read_event",
}


def require_oob(action: str, params: Dict, reason: str = "") -> Dict[str, Any]:
    """Decorator + function: request OOB approval for a destructive action.

    Returns:
        {"approved": bool, "request_id": ..., "reason": ...}
    """
    try:
        from goodware.human_factor.out_of_band import OOBQueue
        q = OOBQueue()
        # Register so ConstitutionalGuard I7 detects conflicts
        target = params.get("path", params.get("snapshot_id", params.get("ip", params.get("pid", ""))))
        ConstitutionalGuard.register_pending_oob(action, str(target))
        req_id = q.enqueue({
            "action": action,
            "params": params,
            "reason": reason or f"Constitutional Guard requires OOB for '{action}'",
            "requested_at": time.time(),
        })
        return {
            "approved": False,
            "pending": True,
            "request_id": req_id,
            "reason": "pending OOB approval",
        }
    except Exception as e:
        return {"approved": False, "error": str(e)}


def require_multiparty(action: str, params: Dict, required: int = 2, total: int = 3) -> Dict[str, Any]:
    """Request multi-party approval for a critical destructive action."""
    try:
        from goodware.human_factor.multi_party import MultiPartyAuthorization
        mpa = MultiPartyAuthorization()
        target = params.get("path", params.get("snapshot_id", params.get("ip", params.get("pid", ""))))
        request_id = mpa.request(
            {"action": action, "params": params, "target": str(target)},
            required_approvals=required,
            total_approvers=total,
        )
        ConstitutionalGuard.register_pending_oob(action, str(target))
        return {
            "approved": False,
            "pending": True,
            "request_id": request_id,
            "reason": f"multi-party approval required ({required}/{total})",
        }
    except Exception as e:
        return {"approved": False, "error": str(e)}


def authorize_tool_call(
    action: str,
    params: Dict[str, Any],
    role: str = "llm",
    node_id: str = "default",
) -> Dict[str, Any]:
    """Single entry-point for tool authorization.

    Returns:
        {"verdict": "approve"|"reject"|"require_oob"|"require_multiparty",
         "violations": [...], "action": ..., "role": ...}

    If verdict == "approve", the caller may execute the tool.
    Otherwise, the caller MUST handle rejection or request approval.
    """
    guard = ConstitutionalGuard(role=role, node_id=node_id)
    return guard.evaluate(action, params)


def guarded_tool(action_name: str):
    """Decorator that wraps a tool function with authorization checks.

    Usage:
        @guarded_tool("kill_process")
        def kill_process(pid: int, ...):
            ...

    The decorated function returns either the original result, or
    {"rejected": True, "verdict": ..., "violations": [...]} if blocked.
    """
    def decorator(fn: Callable):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            params = kwargs if kwargs else (args[0] if args else {})
            guard = ConstitutionalGuard(role=kwargs.pop("_role", "llm"))
            verdict = guard.check(action_name, params)
            if verdict == GuardVerdict.REJECT:
                return {
                    "rejected": True,
                    "verdict": verdict.value,
                    "violations": [
                        {"id": v.invariant_id, "description": v.description, "details": v.details}
                        for v in guard.violations
                    ],
                    "action": action_name,
                }
            if verdict == GuardVerdict.REQUIRE_OOB:
                # Inform caller that OOB is required
                # The CALLER (not the tool) must request approval; we just return
                # the verdict so the caller can decide
                return {
                    "rejected": True,
                    "verdict": verdict.value,
                    "reason": "OOB approval required before executing this action",
                    "request": require_oob(action_name, dict(params)),
                }
            if verdict == GuardVerdict.REQUIRE_MULTIPARTY:
                return {
                    "rejected": True,
                    "verdict": verdict.value,
                    "reason": "Multi-party approval required",
                    "request": require_multiparty(action_name, dict(params)),
                }
            return fn(*args, **kwargs)
        return wrapper
    return decorator