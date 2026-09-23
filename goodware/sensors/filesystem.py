"""
Goodware v3.0 - File system sensor (watchdog).
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from typing import Dict

from goodware.core.events import EventType
from .base import BaseSensor

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _HAS_WATCHDOG = True
except ImportError:
    _HAS_WATCHDOG = False


_EXECUTABLE_EXT = (".py", ".sh", ".so", ".elf", ".bin", ".bash", ".zsh")


class _Handler(FileSystemEventHandler if _HAS_WATCHDOG else object):
    def __init__(self, sensor: "FileSystemSensor"):
        self.sensor = sensor
        self._last_emit: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _should_emit(self, path: str) -> bool:
        with self._lock:
            now = time.time()
            last = self._last_emit.get(path, 0)
            if now - last < 5.0:
                return False
            self._last_emit[path] = now
            return True

    def _emit(self, action: str, path: str) -> None:
        if not self._should_emit(path):
            return
        try:
            sha = None
            size = 0
            if os.path.isfile(path) and os.path.getsize(path) < 50 * 1024 * 1024:
                size = os.path.getsize(path)
                with open(path, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            sha, size = None, 0
        severity = "medium" if any(path.endswith(e) for e in _EXECUTABLE_EXT) else "low"
        self.sensor.emit(
            EventType.SENSOR_FILE_CHANGE,
            {"action": action, "path": path, "sha256": sha, "size": size},
            severity=severity,
            tags=["fs", action],
        )

    def on_modified(self, event):
        if not event.is_directory:
            self._emit("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._emit("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._emit("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._emit("moved", event.src_path)


class FileSystemSensor(BaseSensor):
    """Monitor de sistema de ficheiros (criações, modificações, deleções)."""

    def __init__(self, name: str, config) -> None:
        super().__init__(name, config)
        self.watch_paths = config.get("sensors.filesystem.watch_paths", ["/etc", "/tmp"])
        self.ignore_patterns = config.get("sensors.filesystem.ignore_patterns", [r".*\.log$", r".*~$"])
        self._observer = None
        self._ignored = [re.compile(p) for p in self.ignore_patterns]

    def _is_ignored(self, path: str) -> bool:
        return any(p.search(path) for p in self._ignored)

    def start(self) -> None:
        super().start()
        if not _HAS_WATCHDOG:
            self.logger.warning("watchdog not installed; FileSystemSensor will not watch paths")
            return
        try:
            self._observer = Observer()
            handler = _Handler(self)
            watched = 0
            for path in self.watch_paths:
                if os.path.isdir(path):
                    self._observer.schedule(handler, path, recursive=False)
                    watched += 1
            if watched > 0:
                self._observer.start()
                self.logger.info(f"  watching {watched} paths: {self.watch_paths}")
        except Exception as e:
            self.logger.error(f"FileSystemSensor start failed: {e}")

    def stop(self) -> None:
        super().stop()
        try:
            if self._observer:
                self._observer.stop()
                self._observer.join(timeout=2)
        except Exception:
            pass
