"""
Goodware v3.0 - Adaptive immune response (auto-learn defensive rules).
"""
from __future__ import annotations
import time
import uuid


class AdaptiveImmuneResponse:
    def __init__(self, name, config):
        self.name = name
        self.config = config
        self.engine = None
        self._running = False
        self._last_evolve = 0

    def attach(self, engine):
        self.engine = engine
        from goodware.core.events import EventType
        engine.bus.subscribe(EventType.SENSOR_PROCESS_ANOMALY, self._on_event)
        engine.bus.subscribe(EventType.SENSOR_FILE_CHANGE, self._on_event)
        engine.bus.subscribe(EventType.SENSOR_NETWORK_ANOMALY, self._on_event)
        engine.bus.subscribe(EventType.SENSOR_CONFIG_CHANGE, self._on_event)

    def _on_event(self, ev):
        try:
            if ev.severity.value in ("high", "critical"):
                self._learn(ev)
        except Exception:
            pass

    def _learn(self, ev):
        try:
            pattern = f"^{ev.type.value}"
            action = "quarantine" if ev.severity.value == "critical" else "alert"
            rule_id = str(uuid.uuid4())[:8]
            self.engine.state.add_rule(
                rule_id, f"learned_{rule_id}", pattern, action, ev.severity.value, "adaptive_immune"
            )
            from goodware.core.events import EventType
            self.engine.emit(EventType.IMMUNE_RULE_LEARNED, {"rule": rule_id, "pattern": pattern, "action": action}, source=self.name)
        except Exception:
            pass

    def evolve(self):
        events = self.engine.state.query_events(limit=200)
        types = {}
        for e in events:
            t = e.get("type", "")
            types[t] = types.get(t, 0) + 1
        top = sorted(types.items(), key=lambda x: -x[1])[:5]
        self._last_evolve = time.time()
        return {"top_patterns": top, "rules_count": len(self.engine.state.list_rules())}

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running, "last_evolve": self._last_evolve}
