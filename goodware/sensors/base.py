"""
Goodware v3.0 - Base sensor class.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from goodware.core.events import Severity


class BaseSensor:
    """Base para todos os sensores."""

    def __init__(self, name: str, config) -> None:
        self.name = name
        self.config = config
        self.engine = None
        self.logger = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def attach(self, engine) -> None:
        self.engine = engine
        self.logger = engine.logger

    def emit(self, event_type, payload, severity: str = "info", tags=None):
        sev = Severity(severity) if isinstance(severity, str) else severity
        return self.engine.emit(
            event_type, payload, severity=sev, source=self.name, tags=tags or []
        )

    def safe_run_forever(self, interval: float, callback: Callable, name: Optional[str] = None) -> None:
        tname = name or f"sensor-{self.name}"
        self._thread = threading.Thread(
            target=self._loop, args=(interval, callback), daemon=True, name=tname
        )
        self._thread.start()

    def _loop(self, interval: float, callback: Callable) -> None:
        while self._running:
            try:
                callback()
            except Exception as e:
                if self.logger:
                    self.logger.error(f"sensor {self.name} iteration failed: {e}")
            time.sleep(interval)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False
