"""
Goodware v3.0 - Event System
Sistema de eventos assíncronos que conecta sensores, motor de decisão e efetores.
Inspirado em barramento de mensagens publish/subscribe.
"""
from __future__ import annotations

import time
import uuid
import enum
import json
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, enum.Enum):
    # Sensores
    SENSOR_FILE_CHANGE = "sensor.file_change"
    SENSOR_PROCESS_ANOMALY = "sensor.process_anomaly"
    SENSOR_NETWORK_ANOMALY = "sensor.network_anomaly"
    SENSOR_CONFIG_CHANGE = "sensor.config_change"
    SENSOR_BEHAVIOR_DRIFT = "sensor.behavior_drift"
    SENSOR_QUANTUM_SUSPECT = "sensor.quantum_suspect"

    # Predição
    PREDICTION_THREAT = "prediction.threat"
    PREDICTION_ANOMALY = "prediction.anomaly"
    PREDICTION_ZERO_DAY = "prediction.zero_day"

    # Decisão
    DECISION_RISK = "decision.risk"
    DECISION_QUORUM_REQUIRED = "decision.quorum_required"
    DECISION_POLICY_TRIGGER = "decision.policy_trigger"

    # Efetor
    ACTION_ISOLATE = "action.isolate"
    ACTION_HOT_PATCH = "action.hot_patch"
    ACTION_ROLLBACK = "action.rollback"
    ACTION_QUARANTINE = "action.quarantine"
    ACTION_BLOCK = "action.block"
    ACTION_NEUTRALIZE = "action.neutralize"

    # Imune
    IMMUNE_RULE_LEARNED = "immune.rule_learned"
    IMMUNE_MODEL_UPDATED = "immune.model_updated"
    IMMUNE_MUTATION_DETECTED = "immune.mutation_detected"

    # Federado
    FED_MODEL_RECEIVED = "federated.model_received"
    FED_GRADIENT_SENT = "federated.gradient_sent"

    # Humano
    HUMAN_VERIFY_REQUIRED = "human.verify_required"
    HUMAN_VERIFY_APPROVED = "human.verify_approved"
    HUMAN_VERIFY_REJECTED = "human.verify_rejected"

    # Sistema
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_ERROR = "system.error"
    SYSTEM_ATTESTATION = "system.attestation"


@dataclass
class Event:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EventType = EventType.SYSTEM_START
    timestamp: float = field(default_factory=time.time)
    source: str = "core"
    severity: Severity = Severity.INFO
    payload: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


Handler = Callable[[Event], None]


class EventBus:
    """Barramento de eventos com pub/sub, persistência e replay."""

    def __init__(self, max_history: int = 10000) -> None:
        self._handlers: Dict[EventType, List[Handler]] = {}
        self._wildcard: List[Handler] = []
        self._history: List[Event] = []
        self._max_history = max_history
        self._lock = threading.RLock()
        self._dropped = 0

    # ---- subscrição ----
    def subscribe(self, event_type: EventType, handler: Handler) -> None:
        with self._lock:
            self._handlers.setdefault(event_type, []).append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        with self._lock:
            self._wildcard.append(handler)

    def unsubscribe(self, event_type: EventType, handler: Handler) -> None:
        with self._lock:
            if event_type in self._handlers and handler in self._handlers[event_type]:
                self._handlers[event_type].remove(handler)

    # ---- publicação ----
    def publish(self, event: Event) -> None:
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._dropped += 1
                self._history = self._history[-self._max_history:]
            handlers = list(self._handlers.get(event.type, [])) + list(self._wildcard)
        # fora do lock para evitar deadlocks
        for h in handlers:
            try:
                h(event)
            except Exception as exc:  # pragma: no cover
                print(f"[EventBus] handler error for {event.type}: {exc}")

    def publish_async(self, event: Event) -> threading.Thread:
        t = threading.Thread(target=self.publish, args=(event,), daemon=True)
        t.start()
        return t

    # ---- consulta ----
    def history(
        self,
        event_type: Optional[EventType] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
    ) -> List[Event]:
        with self._lock:
            items = list(self._history)
        if event_type:
            items = [e for e in items if e.type == event_type]
        if severity:
            items = [e for e in items if e.severity == severity]
        return items[-limit:]

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "history_size": len(self._history),
                "max_history": self._max_history,
                "dropped": self._dropped,
                "handler_count": sum(len(v) for v in self._handlers.values()) + len(self._wildcard),
            }
