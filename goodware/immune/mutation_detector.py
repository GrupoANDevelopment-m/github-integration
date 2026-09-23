"""
Goodware v3.0 - Mutation/polymorphic family detection.
"""
from __future__ import annotations
import json
import os


class MutationDetector:
    FAMILIES = {
        "F1": {"name": "miner", "indicators": ["xmrig", "kdevtmpfsi", "stratum", "cryptonight", "monero"]},
        "F2": {"name": "rat", "indicators": ["reverse_shell", "nc -e", "bash -i", "metasploit"]},
        "F3": {"name": "ransomware", "indicators": ["encrypt", "lock.enc", ".locked", "wanna", "ryuk"]},
        "F4": {"name": "rootkit", "indicators": ["ld.so.preload", "libprocesshider", "diamorphine"]},
        "F5": {"name": "stealer", "indicators": ["mimikatz", "browser_credential", "wallet.dat", "metamask"]},
    }

    def __init__(self, name, config):
        self.name = name
        self.config = config
        self.engine = None
        self._running = False
        self.path = os.path.join(config.get("general.data_dir", "data"), "immune_families.json")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.counters = {k: 0 for k in self.FAMILIES}
        self._save()

    def attach(self, engine):
        self.engine = engine

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump({"counters": self.counters, "families": self.FAMILIES}, f, indent=2)
        except Exception:
            pass

    def analyze_behavior(self, behavior):
        matches = []
        b_lower = {k: str(v).lower() for k, v in behavior.items()}
        for fam_id, fam in self.FAMILIES.items():
            for ind in fam["indicators"]:
                if any(ind in v for v in b_lower.values()):
                    matches.append(fam_id)
                    self.counters[fam_id] = self.counters.get(fam_id, 0) + 1
                    break
        self._save()
        if matches and self.engine:
            try:
                from goodware.core.events import EventType
                self.engine.emit(EventType.IMMUNE_MUTATION_DETECTED, {"families": matches, "behavior": behavior}, source=self.name)
            except Exception:
                pass
        return {"matches": matches}

    def family_count(self):
        return len(self.FAMILIES)

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running, "families": self.family_count(), "counters": self.counters}
