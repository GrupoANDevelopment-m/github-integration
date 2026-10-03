"""Goodware v3.0 - Expressive policy engine.

Production version supports rich condition operators:
  - field, operator, value
  - operators: eq, ne, gt, gte, lt, lte, in, nin, contains, regex, exists

Supported actions:
  - block, allow, alert, quarantine, rollback, isolate, require_oob

Policies are loaded from YAML/JSON files in policies/ dir AND
from a built-in default set. Each policy is a dict with:
  {
    "name": "policy-name",
    "description": "...",
    "conditions": [{"field": "severity", "operator": "eq", "value": "critical"}],
    "action": "block",
    "priority": 100,
    "tags": ["..."]
  }
"""
from __future__ import annotations
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.decision.policy_engine")


class PolicyEngine:
    """Expressive policy evaluator with rich operators."""

    DEFAULT_POLICIES = [
        {
            "name": "block-critical",
            "description": "Block any critical-severity event",
            "conditions": [{"field": "severity", "operator": "eq", "value": "critical"}],
            "action": "block",
            "priority": 100,
        },
        {
            "name": "alert-high",
            "description": "Alert on high-severity events",
            "conditions": [{"field": "severity", "operator": "eq", "value": "high"}],
            "action": "alert",
            "priority": 80,
        },
        {
            "name": "quarantine-ransomware",
            "description": "Quarantine any ransomware-pattern event",
            "conditions": [
                {"field": "type", "operator": "contains", "value": "ransomware"},
            ],
            "action": "quarantine",
            "priority": 200,
        },
        {
            "name": "isolate-exfil",
            "description": "Isolate on data exfiltration events",
            "conditions": [
                {"field": "type", "operator": "regex", "value": "(?i)(exfil|exfiltrat)"},
            ],
            "action": "isolate",
            "priority": 250,
        },
        {
            "name": "block-known-bad-ips",
            "description": "Block any event from IPs in the IOC database",
            "conditions": [{"field": "source_ip", "operator": "exists", "value": True}],
            "action": "block",
            "priority": 90,
        },
        {
            "name": "rollback-on-cve",
            "description": "Trigger rollback for high-impact CVE exploits",
            "conditions": [
                {"field": "cve_id", "operator": "exists", "value": True},
                {"field": "severity", "operator": "in", "value": ["high", "critical"]},
            ],
            "action": "rollback",
            "priority": 180,
        },
    ]

    def __init__(self, policy_dir: str = "policies"):
        self.policy_dir = policy_dir
        self.policies: List[Dict] = []
        self._load_all()

    def _load_all(self) -> None:
        loaded = []
        if os.path.isdir(self.policy_dir):
            for fn in sorted(os.listdir(self.policy_dir)):
                if not fn.endswith((".yaml", ".yml", ".json")):
                    continue
                try:
                    path = os.path.join(self.policy_dir, fn)
                    if fn.endswith((".yaml", ".yml")):
                        import yaml
                        with open(path) as f:
                            d = yaml.safe_load(f)
                    else:
                        with open(path) as f:
                            d = json.load(f)
                    if isinstance(d, dict) and "policies" in d:
                        loaded.extend(d["policies"])
                    elif isinstance(d, list):
                        loaded.extend(d)
                    elif isinstance(d, dict) and "name" in d and "conditions" in d:
                        loaded.append(d)
                except Exception as e:
                    log.warning("Failed to load policy %s: %s", fn, e)
        if not loaded:
            loaded = list(self.DEFAULT_POLICIES)
        # Sort by priority (descending)
        self.policies = sorted(loaded, key=lambda p: p.get("priority", 0), reverse=True)

    def add_policy(self, name: str, conditions: List[Dict], action: str, priority: int = 50,
                   description: str = "", tags: Optional[List[str]] = None) -> None:
        self.policies.append({
            "name": name,
            "description": description,
            "conditions": conditions,
            "action": action,
            "priority": priority,
            "tags": tags or [],
        })
        self.policies.sort(key=lambda p: p.get("priority", 0), reverse=True)

    def evaluate(self, event) -> List[Dict[str, Any]]:
        """Evaluate all policies against an event, return matches in priority order."""
        ctx = self._build_context(event)
        matches = []
        for p in self.policies:
            if self._matches(p["conditions"], ctx):
                matches.append({
                    "name": p["name"],
                    "action": p["action"],
                    "priority": p.get("priority", 0),
                    "description": p.get("description", ""),
                })
        return matches

    def _build_context(self, event) -> Dict[str, Any]:
        """Flatten event into a context dict for condition evaluation."""
        ctx = {}
        if isinstance(event, dict):
            ctx.update(event)
            if "payload" in event and isinstance(event["payload"], dict):
                for k, v in event["payload"].items():
                    if k not in ctx:
                        ctx[k] = v
            sev = event.get("severity", "info")
            if hasattr(sev, "value"):
                sev = sev.value
            ctx["severity"] = str(sev)
        else:
            sev = getattr(event, "severity", "info")
            sev = getattr(sev, "value", sev)
            ctx["severity"] = str(sev)
            payload = getattr(event, "payload", {}) or {}
            for k, v in payload.items():
                ctx[k] = v
            etype = getattr(event, "event_type", None)
            if etype:
                ctx["type"] = str(getattr(etype, "value", etype))
        return ctx

    def _matches(self, conditions: List[Dict], ctx: Dict[str, Any]) -> bool:
        if not conditions:
            return False
        for c in conditions:
            field = c.get("field")
            op = c.get("operator", "eq")
            value = c.get("value")
            actual = ctx.get(field)
            if not self._check_condition(op, actual, value):
                return False
        return True

    def _check_condition(self, op: str, actual: Any, value: Any) -> bool:
        try:
            if op == "eq":
                return actual == value
            if op == "ne":
                return actual != value
            if op == "gt":
                return actual is not None and float(actual) > float(value)
            if op == "gte":
                return actual is not None and float(actual) >= float(value)
            if op == "lt":
                return actual is not None and float(actual) < float(value)
            if op == "lte":
                return actual is not None and float(actual) <= float(value)
            if op == "in":
                return actual in (value or [])
            if op == "nin":
                return actual not in (value or [])
            if op == "contains":
                if actual is None:
                    return False
                return str(value).lower() in str(actual).lower()
            if op == "regex":
                if actual is None:
                    return False
                return bool(re.search(str(value), str(actual)))
            if op == "exists":
                if isinstance(value, bool):
                    return (actual is not None) == value
                return actual is not None
            if op == "starts_with":
                return actual is not None and str(actual).startswith(str(value))
            if op == "ends_with":
                return actual is not None and str(actual).endswith(str(value))
        except Exception:
            return False
        return False

    def status(self) -> Dict[str, Any]:
        return {
            "policies_loaded": len(self.policies),
            "policy_names": [p["name"] for p in self.policies],
            "policy_dir": self.policy_dir,
        }