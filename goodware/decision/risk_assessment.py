"""Goodware v3.0 - Multi-factor risk assessment."""
from __future__ import annotations


class RiskAssessor:
    SEV_W = {"info": 0.1, "low": 0.25, "medium": 0.55, "high": 0.8, "critical": 0.95}

    def __init__(self, config):
        self.config = config

    def assess(self, event):
        if isinstance(event, dict):
            sev = event.get("severity", "info")
            payload = event.get("payload", {})
        else:
            sev = getattr(event, "severity", "info")
            sev = getattr(sev, "value", sev)
            payload = getattr(event, "payload", {})
        if hasattr(sev, "value"):
            sev = sev.value
        base = self.SEV_W.get(sev, 0.3)
        if isinstance(payload, dict):
            for v in payload.values():
                if isinstance(v, str) and "cve" in v.lower():
                    base = min(1.0, base + 0.1)
                    break
        return round(base, 3)
