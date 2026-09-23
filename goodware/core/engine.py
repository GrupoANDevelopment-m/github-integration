"""
Goodware v3.0 - Engine principal
Liga todas as camadas (sensores, predição, decisão, efetores) via barramento de eventos.
"""
from __future__ import annotations

import os
import signal
import threading
import time
from typing import Any, Dict, List, Optional

from .config import GoodwareConfig
from .events import Event, EventBus, EventType, Severity
from .logger import get_logger
from .state import StateStore


class Engine:
    """Motor central do Goodware v3.0."""

    def __init__(self, config: GoodwareConfig) -> None:
        self.config = config
        self.bus = EventBus()
        self.logger = get_logger("goodware.engine", config.get("general.log_dir", "logs"))
        data_dir = config.get("general.data_dir", "data")
        os.makedirs(data_dir, exist_ok=True)
        self.state = StateStore(os.path.join(data_dir, "goodware.db"))
        self._components: Dict[str, Any] = {}
        self._running = False
        self._threads: List[threading.Thread] = []
        self._lock = threading.RLock()
        self._register_default_subscribers()
        self.bus.subscribe(EventType.SYSTEM_START, self._on_system_start)

    # ---- ciclo de vida ----
    def register(self, name: str, component: Any) -> None:
        with self._lock:
            self._components[name] = component
            if hasattr(component, "attach"):
                component.attach(self)
        self.logger.info(f"component registered: {name}")

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.logger.info("=" * 60)
        self.logger.info("Goodware v3.0 starting...")
        self.logger.info(f"  node_id: {self.config.get('general.node_id')}")
        self.logger.info(f"  organization: {self.config.get('general.organization')}")
        self.logger.info("=" * 60)
        self.bus.publish(
            Event(
                type=EventType.SYSTEM_START,
                source="engine",
                severity=Severity.INFO,
                payload={"components": list(self._components.keys())},
            )
        )
        for name, comp in self._components.items():
            try:
                if hasattr(comp, "start"):
                    t = threading.Thread(target=self._safe_start, args=(name, comp), daemon=True, name=f"start-{name}")
                    t.start()
                    self._threads.append(t)
            except Exception as e:
                self.logger.error(f"failed to start {name}: {e}")

    def _safe_start(self, name: str, comp: Any) -> None:
        try:
            comp.start()
            self.logger.info(f"  ✓ {name} running")
        except Exception as e:
            self.logger.error(f"  ✗ {name} crashed at start: {e}")
            self.bus.publish(Event(type=EventType.SYSTEM_ERROR, source=name, severity=Severity.HIGH,
                                    payload={"error": str(e)}))

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self.bus.publish(Event(type=EventType.SYSTEM_STOP, source="engine", severity=Severity.INFO))
        for name, comp in self._components.items():
            try:
                if hasattr(comp, "stop"):
                    comp.stop()
            except Exception as e:
                self.logger.error(f"error stopping {name}: {e}")
        self.logger.info("Goodware stopped.")

    def run_forever(self) -> None:
        self.start()
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()

    # ---- helpers ----
    def get(self, name: str) -> Optional[Any]:
        return self._components.get(name)

    def emit(self, event_type: EventType, payload: Dict[str, Any],
             severity: Severity = Severity.INFO, source: str = "engine",
             correlation_id: Optional[str] = None, tags: Optional[List[str]] = None) -> Event:
        ev = Event(
            type=event_type,
            source=source,
            severity=severity,
            payload=payload,
            correlation_id=correlation_id,
            tags=tags or [],
        )
        self.bus.publish(ev)
        try:
            self.state.record_event(ev.to_dict())
        except Exception as e:
            self.logger.error(f"persist event failed: {e}")
        return ev

    def _register_default_subscribers(self) -> None:
        # Regista todos os eventos críticos na BD via callback
        def persist(ev: Event) -> None:
            try:
                self.state.record_event(ev.to_dict())
            except Exception:
                pass
        self.bus.subscribe_all(persist)

    def _on_system_start(self, ev: Event) -> None:
        self.state.audit("engine", "system_start", "goodware", "ok", "boot complete")

    # ---- estado ----
    def status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "node_id": self.config.get("general.node_id"),
            "organization": self.config.get("general.organization"),
            "components": list(self._components.keys()),
            "bus": self.bus.stats(),
        }
