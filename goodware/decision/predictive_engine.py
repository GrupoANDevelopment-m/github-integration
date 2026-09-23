"""Goodware v3.0 - Predictive decision engine."""
from __future__ import annotations


class PredictiveEngine:
    def __init__(self, name, config):
        self.name = name
        self.config = config
        self.engine = None
        self._running = False

    def attach(self, engine):
        self.engine = engine
        engine.bus.subscribe_all(self._on_event)

    def _on_event(self, ev):
        try:
            from goodware.core.events import EventType
            if ev.severity.value in ("high", "critical"):
                risk = 0.95 if ev.severity.value == "critical" else 0.8
                self.engine.emit(
                    EventType.DECISION_RISK,
                    {"event_id": ev.id, "type": ev.type.value, "risk": risk},
                    source="decision",
                )
        except Exception:
            pass

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running}
