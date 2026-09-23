"""Red-team AI: simulates attacks to test defenses."""
from __future__ import annotations
import random
import time
import threading


ATTACK_TEMPLATES = [
    {"name": "port_scan", "type": "sensor.network_anomaly", "severity": "medium", "payload": {"port": 22, "rate": 100}},
    {"name": "brute_force_ssh", "type": "sensor.behavior_drift", "severity": "high", "payload": {"user": "root", "fails": 50}},
    {"name": "web_exploit_attempt", "type": "sensor.network_anomaly", "severity": "high", "payload": {"uri": "/admin.php?cmd=id"}},
    {"name": "ransomware_drop", "type": "sensor.file_change", "severity": "critical", "payload": {"path": "/tmp/lock.enc"}},
    {"name": "lateral_smb", "type": "sensor.network_anomaly", "severity": "high", "payload": {"target_ip": "10.0.0.5"}},
    {"name": "phishing_link", "type": "sensor.behavior_drift", "severity": "medium", "payload": {"link": "http://evil.example"}},
    {"name": "supply_chain_swap", "type": "sensor.config_change", "severity": "critical", "payload": {"file": "/etc/passwd"}},
    {"name": "credential_dump", "type": "sensor.process_anomaly", "severity": "high", "payload": {"proc": "mimikatz"}},
    {"name": "rootkit_install", "type": "sensor.file_change", "severity": "critical", "payload": {"path": "/etc/ld.so.preload"}},
    {"name": "data_exfil", "type": "sensor.network_anomaly", "severity": "high", "payload": {"bytes_out": 500_000_000}},
]


class AttackSimulator:
    def __init__(self, name: str, config):
        self.name = name
        self.config = config
        self.engine = None
        self._running = False
        self._thread = None
        self._last_eval = None

    def attach(self, engine):
        self.engine = engine
        self.logger = engine.logger

    def simulate(self, n: int = 1):
        from goodware.core.events import EventType, Severity
        from goodware.core.events import Event
        injected = []
        for _ in range(n):
            tmpl = random.choice(ATTACK_TEMPLATES)
            try:
                et = EventType(tmpl["type"])
            except ValueError:
                et = EventType.SENSOR_PROCESS_ANOMALY
            sev = Severity(tmpl["severity"])
            ev = Event(
                type=et,
                source="simulator",
                severity=sev,
                payload={**tmpl["payload"], "template": tmpl["name"]},
                tags=["simulation", tmpl["name"]],
            )
            self.engine.bus.publish(ev)
            self.engine.state.record_event(ev.to_dict())
            injected.append(tmpl["name"])
        return {"injected": injected, "n": n}

    def evaluate_defense(self):
        # query events tagged 'simulation' and look for downstream actions
        events = self.engine.state.query_events(limit=500)
        sim = [e for e in events if "simulation" in (e.get("tags") or [])]
        actions = [e for e in events if e.get("type", "").startswith("action.")]
        coverage = (len(actions) / max(1, len(sim))) if sim else 0.0
        self._last_eval = {"simulated": len(sim), "actions_taken": len(actions), "coverage": coverage}
        try:
            import json, os
            os.makedirs("models", exist_ok=True)
            with open("models/simulator_eval.json", "w") as f:
                json.dump(self._last_eval, f)
        except Exception:
            pass
        return self._last_eval

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="attack-simulator")
        self._thread.start()

    def _loop(self):
        interval = 60  # every minute
        while self._running:
            try:
                self.simulate(random.randint(1, 2))
                time.sleep(5)
                self.evaluate_defense()
            except Exception as e:
                self.logger.error(f"simulator: {e}")
            time.sleep(interval)

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running, "last_eval": self._last_eval}
