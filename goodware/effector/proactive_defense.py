"""Goodware v3.0 - Proactive defense (pre-emptive firewall from predictions)."""
from __future__ import annotations


class ProactiveDefense:
    def __init__(self, engine, firewall, config):
        self.engine = engine
        self.firewall = firewall
        self.config = config

    def apply_prediction(self, pred):
        rules = []
        tt = pred.get("threat_type", "")
        if tt == "brute_force":
            rules.append({"action": "tighten_ssh", "reason": tt})
        elif tt == "scan":
            rules.append({"action": "tighten_firewall", "reason": tt})
        elif tt == "ransomware_precursor":
            self.firewall.block_port(445, "tcp", reason="block_smb_for_ransomware_precursor")
            rules.append({"action": "block_smb", "reason": tt})
        try:
            from goodware.core.events import EventType
            self.engine.emit(EventType.ACTION_BLOCK, {"rules": rules, "pred": pred}, source="proactive-defense")
        except Exception:
            pass
        return {"ok": True, "rules": rules}

    def apply_zero_day(self, zd):
        service = zd.get("service", "")
        port = {"sshd": 22, "http": 80, "smb": 445, "pan-os": 443, "confluence": 8090, "fortra": 8443}.get(service)
        rules = []
        if port:
            self.firewall.block_port(port, "tcp", reason=f"zero_day:{zd.get('cve')}")
            rules.append({"action": "virtual_patch", "port": port, "cve": zd.get("cve")})
        return {"ok": True, "rules": rules}
