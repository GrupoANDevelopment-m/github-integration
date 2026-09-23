"""
Goodware v3.0 - Config sensor (watches critical system files).
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Dict

from goodware.core.events import EventType
from .base import BaseSensor


class ConfigSensor(BaseSensor):
    """Vigia ficheiros críticos: /etc/passwd, sudoers, sshd_config, crontab."""

    def __init__(self, name: str, config) -> None:
        super().__init__(name, config)
        self.files = config.get(
            "sensors.config.watch_files",
            ["/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab"],
        )
        self._hashes: Dict[str, str] = {}
        self._lock = threading.Lock()
        self.interval = 10

    def _hash(self, path: str) -> str:
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def _scan(self) -> None:
        for path in self.files:
            if not os.path.exists(path):
                continue
            try:
                with self._lock:
                    h_old = self._hashes.get(path, "")
                    h_new = self._hash(path)
                    if not h_new:
                        continue
                    if h_old and h_old != h_new:
                        self._emit_change(path, h_old, h_new)
                    self._hashes[path] = h_new
            except Exception as e:
                if self.logger:
                    self.logger.error(f"config sensor: {path}: {e}")

    def _emit_change(self, path: str, h_old: str, h_new: str) -> None:
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            content = ""
        severity = "high"
        reason = "modified"
        # critical patterns
        if "passwd" in os.path.basename(path):
            for line in content.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split(":")
                if len(parts) >= 3 and parts[2] == "0" and parts[0] not in ("root",):
                    severity = "critical"
                    reason = "new_uid_zero_user"
                    break
        if "sudoers" in path and "NOPASSWD" in content:
            severity = "critical"
            reason = "sudoers_nopasswd"
        if "crontab" in path and content != "":
            for line in content.splitlines():
                if line.strip() and not line.startswith("#"):
                    if any(p in line.lower() for p in ["curl", "wget", "base64"]):
                        severity = "high"
                        reason = "suspicious_cron"
                        break
        self.emit(
            EventType.SENSOR_CONFIG_CHANGE,
            {"path": path, "old_hash": h_old[:12], "new_hash": h_new[:12], "reason": reason},
            severity=severity,
            tags=["config", reason],
        )

    def start(self) -> None:
        super().start()
        for path in self.files:
            if os.path.exists(path):
                self._hashes[path] = self._hash(path)
        self.safe_run_forever(self.interval, self._scan, name="sensor-config")

    def stop(self) -> None:
        super().stop()
