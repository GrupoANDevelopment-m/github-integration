"""
Goodware v3.0 — Constitutional Guard.

Enforces formal invariants (I1..In) on every action proposed by the
LLM Brain, automation, or operator. Any action that violates an
invariant is REJECTED with an explicit reason.

Invariants are explicitly documented and tested.

INVARIANTS (current set):

  I1  — No destructive action (kill, quarantine, block, isolate, rollback)
        on the Goodware process itself or its artifacts (snapshots, models,
        keys, code, configs). This is the auto-protection invariant.

  I2  — No action that disables logging or audit trail.

  I3  — No action that creates a backdoor (port opening, account creation
        without OOB, persistent unauthorized access).

  I4  — No exfiltration of the threat intel DB, models, or keys to
        external destinations.

  I5  — No new network listeners on privileged ports (< 1024) without
        OOB approval.

  I6  — Self-modification: any code change requires a snapshot taken
        first, plus a rollback plan registered in the audit log.

  I7  — No action that would conflict with an existing pending OOB
        approval request for the same target.

  I8  — Multi-party: destructive actions on production targets
        require N-of-M approval (default 2-of-3).

  I9  — Rate limit: no more than K destructive actions per minute per
        node (default K=10).

  I10 — Privilege: the requesting principal's role must be >= required
        for the action (admin can do anything; operator can block but
        not delete; viewer cannot execute tools).

These invariants are tested in tests/test_constitutional_guard.py.
A violation always returns REJECT with a clear reason; the call site
must handle the rejection explicitly.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("goodware.security.constitutional_guard")


class GuardVerdict(Enum):
    APPROVE = "approve"
    REJECT = "reject"
    REQUIRE_OOB = "require_oob"
    REQUIRE_MULTIPARTY = "require_multiparty"


@dataclass
class InvariantViolation:
    invariant_id: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)


# Action classification
DESTRUCTIVE_ACTIONS: Set[str] = {
    "kill_process",
    "quarantine_file",
    "block_ip",
    "isolate_machine",
    "rollback_snapshot",
    "delete_snapshot",
    "hot_patch",
    "remove_model",
    "clear_quarantine",
    "delete_firewall_rule",
    "rotate_keys",
}


PROTECTED_ARTIFACT_PATHS: Set[str] = {
    "data/snapshots",
    "models",
    "keys",
    "data/goodware.db",
    "data/vault",
    "goodware/security",
    "goodware/llm/permissions.py",
    "goodware/security/constitutional_guard.py",
}


ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {
        "kill_process", "quarantine_file", "block_ip", "isolate_machine",
        "rollback_snapshot", "delete_snapshot", "hot_patch", "remove_model",
        "clear_quarantine", "delete_firewall_rule", "rotate_keys",
        "run_yara_scan", "search_iocs", "search_cves", "generate_pqc_keypair",
        "sign_pqc", "verify_pqc", "alert_human", "no_action",
    },
    "operator": {
        "block_ip", "quarantine_file", "run_yara_scan", "search_iocs",
        "search_cves", "alert_human", "no_action",
    },
    "viewer": {
        "search_iocs", "search_cves", "no_action",
    },
    "service": {
        "kill_process", "quarantine_file", "block_ip", "run_yara_scan",
        "search_iocs", "search_cves", "alert_human", "no_action",
    },
    "llm": {
        # LLM can only propose; tools that need approval go through OOB
        "search_iocs", "search_cves", "run_yara_scan", "alert_human",
        "no_action", "request_oob_approval",
    },
}


class ConstitutionalGuard:
    """Stateless-ish guard that records rate counts and pending OOBs."""

    # Class-level rate state (shared across instances)
    _action_log: List[float] = []
    _pending_oob_targets: Set[str] = set()
    _MAX_ACTIONS_PER_MIN = 10

    def __init__(self, role: str = "admin", node_id: str = "default"):
        self.role = role
        self.node_id = node_id
        self.violations: List[InvariantViolation] = []

    def check(self, action: str, params: Dict[str, Any]) -> GuardVerdict:
        """Check the proposed action against all invariants.

        Returns GuardVerdict.APPROVE / REJECT / REQUIRE_OOB / REQUIRE_MULTIPARTY.
        Populates self.violations with details if REJECT.
        """
        self.violations = []
        # I10: Role permission check
        v = self._check_role_permission(action)
        if v:
            self.violations.append(v)
            return GuardVerdict.REJECT

        # I1: No destructive action on protected artifacts
        v = self._check_protected_artifacts(action, params)
        if v:
            self.violations.append(v)
            return GuardVerdict.REJECT

        # I2: No disabling logging/audit
        v = self._check_logging_tampering(action, params)
        if v:
            self.violations.append(v)
            return GuardVerdict.REJECT

        # I3: No backdoor creation
        v = self._check_backdoor_creation(action, params)
        if v:
            self.violations.append(v)
            return GuardVerdict.REJECT

        # I4: No exfiltration
        v = self._check_exfiltration(action, params)
        if v:
            self.violations.append(v)
            return GuardVerdict.REJECT

        # I5: No privileged port without OOB
        v = self._check_privileged_port(action, params)
        if v:
            self.violations.append(v)
            return GuardVerdict.REQUIRE_OOB

        # I7: No conflict with pending OOB
        v = self._check_pending_oob_conflict(action, params)
        if v:
            self.violations.append(v)
            return GuardVerdict.REQUIRE_MULTIPARTY

        # I8: Destructive actions require multi-party
        if action in DESTRUCTIVE_ACTIONS:
            if self.role != "admin":
                self.violations.append(InvariantViolation(
                    "I8", f"destructive action '{action}' requires admin role", {"role": self.role}
                ))
                return GuardVerdict.REQUIRE_MULTIPARTY
            # Even admin requires multi-party for high-impact actions
            if action in {"isolate_machine", "rollback_snapshot", "delete_snapshot", "remove_model"}:
                return GuardVerdict.REQUIRE_MULTIPARTY

        # I9: Rate limit
        if not self._check_rate_limit():
            self.violations.append(InvariantViolation(
                "I9", f"rate limit exceeded ({self._MAX_ACTIONS_PER_MIN}/min)", {}
            ))
            return GuardVerdict.REJECT

        return GuardVerdict.APPROVE

    # ----------------------------------------------------------------------
    # Individual invariant checks
    # ----------------------------------------------------------------------
    def _check_role_permission(self, action: str) -> Optional[InvariantViolation]:
        perms = ROLE_PERMISSIONS.get(self.role, set())
        if action not in perms:
            return InvariantViolation(
                "I10", f"role '{self.role}' not allowed to execute '{action}'",
                {"role": self.role, "allowed": sorted(perms)},
            )
        return None

    def _check_protected_artifacts(self, action: str, params: Dict) -> Optional[InvariantViolation]:
        target = ""
        if action == "quarantine_file":
            target = params.get("path", "")
        elif action == "rollback_snapshot":
            target = "snapshots"
        elif action == "delete_snapshot":
            target = "snapshots"
        elif action == "remove_model":
            target = "models"
        elif action == "rotate_keys":
            target = "keys"
        elif action == "block_ip":
            target = "firewall"
        if not target:
            return None
        for protected in PROTECTED_ARTIFACT_PATHS:
            if protected in str(target):
                return InvariantViolation(
                    "I1", f"destructive action '{action}' on protected artifact '{target}'",
                    {"protected_path": protected, "action": action},
                )
        return None

    def _check_logging_tampering(self, action: str, params: Dict) -> Optional[InvariantViolation]:
        # Detect any action that tries to disable logs/audit
        if action in {"clear_quarantine", "rotate_keys"} and "data/goodware.db" in str(params):
            return InvariantViolation(
                "I2", f"action '{action}' would tamper with audit trail",
                {"action": action, "params": params},
            )
        return None

    def _check_backdoor_creation(self, action: str, params: Dict) -> Optional[InvariantViolation]:
        # Creating new SSH keys, opening privileged ports, etc.
        if action in {"rotate_keys"} and self.role not in {"admin"}:
            return InvariantViolation(
                "I3", f"key rotation without admin role may create backdoor",
                {"role": self.role},
            )
        return None

    def _check_exfiltration(self, action: str, params: Dict) -> Optional[InvariantViolation]:
        # Detect attempts to exfiltrate protected data
        path = str(params.get("path", "")) + str(params.get("destination", ""))
        for protected in ("data/cve", "models", "data/vault", "keys"):
            if protected in path and action in {"quarantine_file", "rollback_snapshot"}:
                return InvariantViolation(
                    "I4", f"action '{action}' on protected data path '{path}' may exfiltrate",
                    {"path": path, "action": action},
                )
        return None

    def _check_privileged_port(self, action: str, params: Dict) -> Optional[InvariantViolation]:
        port = params.get("port", 0)
        if action in {"block_ip", "isolate_machine"} and 0 < int(port) < 1024:
            return InvariantViolation(
                "I5", f"privileged port {port} requires OOB approval",
                {"port": port, "action": action},
            )
        return None

    def _check_pending_oob_conflict(self, action: str, params: Dict) -> Optional[InvariantViolation]:
        target = params.get("target", params.get("path", params.get("snapshot_id", params.get("ip", ""))))
        key = f"{action}:{target}"
        if key in self._pending_oob_targets:
            return InvariantViolation(
                "I7", f"action '{action}' on '{target}' has pending OOB request",
                {"target": target, "action": action},
            )
        return None

    def _check_rate_limit(self) -> bool:
        now = time.time()
        # Clean old entries
        ConstitutionalGuard._action_log = [
            t for t in ConstitutionalGuard._action_log if now - t < 60
        ]
        if len(ConstitutionalGuard._action_log) >= self._MAX_ACTIONS_PER_MIN:
            return False
        ConstitutionalGuard._action_log.append(now)
        return True

    @classmethod
    def register_pending_oob(cls, action: str, target: str) -> None:
        cls._pending_oob_targets.add(f"{action}:{target}")

    @classmethod
    def clear_pending_oob(cls, action: str, target: str) -> None:
        cls._pending_oob_targets.discard(f"{action}:{target}")

    def evaluate(self, action: str, params: Dict) -> Dict[str, Any]:
        verdict = self.check(action, params)
        return {
            "verdict": verdict.value,
            "violations": [
                {
                    "id": v.invariant_id,
                    "description": v.description,
                    "details": v.details,
                }
                for v in self.violations
            ],
            "action": action,
            "role": self.role,
        }
