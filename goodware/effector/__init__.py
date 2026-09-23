"""Goodware v3.0 - Effector module (real iptables/kill/YARA/ClamAV)."""
from .quarantine import Quarantine
from .firewall import Firewall
from .hot_patch import HotPatch
from .rollback import Rollback
from .proactive_defense import ProactiveDefense
import os


class EffectorManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.quarantine = Quarantine(engine)
        self.firewall = Firewall()
        self.hotpatch = HotPatch(engine)
        self.rollback = Rollback()
        self.proactive = ProactiveDefense(engine, self.firewall, config)
        from goodware.core.events import EventType
        engine.bus.subscribe(EventType.DECISION_RISK, self._on_decision)
        engine.bus.subscribe(EventType.PREDICTION_THREAT, self._on_prediction)
        engine.bus.subscribe(EventType.PREDICTION_ZERO_DAY, self._on_zero_day)

    def _on_decision(self, ev):
        try:
            if ev.payload.get("risk", 0) > 0.9:
                self.execute_action({"type": "noop", "reason": "high_risk_recorded"})
        except Exception:
            pass

    def _on_prediction(self, ev):
        try:
            self.proactive.apply_prediction(ev.payload)
        except Exception:
            pass

    def _on_zero_day(self, ev):
        try:
            self.proactive.apply_zero_day(ev.payload)
        except Exception:
            pass

    def start(self):
        return True

    def stop(self):
        pass

    def execute_action(self, action):
        t = action.get("type", "")
        target = action.get("target", "")
        reason = action.get("reason", "")
        pid = action.get("pid")
        if t == "quarantine" and target and os.path.isfile(target):
            return self.quarantine.quarantine(target, reason, kill_pid=pid)
        if t == "block_ip":
            return self.firewall.block_ip(target, reason)
        if t == "block_port":
            try:
                return self.firewall.block_port(int(target), "tcp", reason)
            except Exception:
                return {"ok": False, "error": "invalid_port"}
        if t == "kill":
            try:
                return self.quarantine.kill_process(int(target))
            except Exception:
                return {"ok": False, "error": "invalid_pid"}
        if t == "kill_tree":
            try:
                return self.quarantine.kill_process_tree(int(target))
            except Exception:
                return {"ok": False, "error": "invalid_pid"}
        if t == "restore":
            return self.quarantine.restore(target)
        if t == "hot_patch":
            return self.hotpatch.apply(action.get("id", "manual"), target, action)
        if t == "snapshot":
            return self.rollback.snapshot(reason, action.get("paths", []))
        if t == "noop":
            return {"ok": True, "noop": True}
        return {"ok": True, "noop": True, "action": action}

    def firewall_snapshot(self):
        return self.firewall.snapshot()
