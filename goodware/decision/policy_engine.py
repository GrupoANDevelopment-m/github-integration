"""Goodware v3.0 - Policy engine."""
from __future__ import annotations
import os


class PolicyEngine:
    def __init__(self, policy_dir="policies"):
        self.policy_dir = policy_dir
        self.policies = self._load_all()
        if not self.policies:
            self.policies = [
                {"name": "block-critical", "conditions": [{"field": "severity", "value": "critical"}], "action": "block"},
                {"name": "alert-high", "conditions": [{"field": "severity", "value": "high"}], "action": "alert"},
                {"name": "quarantine-suspicious-process", "conditions": [{"field": "type", "value": "sensor.process_anomaly"}], "action": "quarantine"},
            ]

    def _load_all(self):
        out = []
        if not os.path.isdir(self.policy_dir):
            return out
        for fn in os.listdir(self.policy_dir):
            if not fn.endswith((".yaml", ".yml", ".json")):
                continue
            try:
                if fn.endswith((".yaml", ".yml")):
                    import yaml
                    with open(os.path.join(self.policy_dir, fn)) as f:
                        d = yaml.safe_load(f)
                else:
                    import json
                    with open(os.path.join(self.policy_dir, fn)) as f:
                        d = json.load(f)
                if isinstance(d, dict) and "policies" in d:
                    out.extend(d["policies"])
                elif isinstance(d, list):
                    out.extend(d)
            except Exception:
                pass
        return out

    def evaluate(self, event):
        matches = []
        if isinstance(event, dict):
            sev = event.get("severity", "info")
            ttype = event.get("type", "")
        else:
            sev = getattr(event, "severity", "info")
            sev = getattr(sev, "value", sev)
            ttype = getattr(event, "type", "")
            ttype = getattr(ttype, "value", ttype)
        for p in self.policies:
            ok = True
            for c in p.get("conditions", []):
                field = c.get("field")
                if field == "severity" and c.get("value") != sev:
                    ok = False
                    break
                if field == "type" and c.get("value") != ttype:
                    ok = False
                    break
            if ok:
                matches.append({"name": p["name"], "action": p["action"]})
        return matches

    def add_policy(self, name, conditions, action):
        self.policies.append({"name": name, "conditions": conditions, "action": action})
