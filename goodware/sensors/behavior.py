"""
Goodware v3.0 - Behavior sensor (login patterns, privilege escalation).
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict, deque
from typing import Dict

from goodware.core.events import EventType
from .base import BaseSensor


class BehaviorSensor(BaseSensor):
    """Monitoriza logins falhados, escalação de privilégios e drift comportamental."""

    _SUDO_RE = re.compile(r"sudo:\s+(\S+)\s+:")
    _FAILED_RE = re.compile(r"Failed password for(?:\s+invalid user)?\s+(\S+)\s+from\s+(\S+)")

    def __init__(self, name: str, config) -> None:
        super().__init__(name, config)
        self.interval = 15
        self.auth_log = "/var/log/auth.log"
        if not os.path.exists(self.auth_log):
            for alt in ("/var/log/secure",):
                if os.path.exists(alt):
                    self.auth_log = alt
                    break
        self._last_pos = 0
        self._fail_window: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._baseline_path = os.path.join(
            config.get("general.data_dir", "data"), "behavior_baseline.json"
        )
        self._ensure_baseline()

    def _ensure_baseline(self) -> None:
        os.makedirs(os.path.dirname(self._baseline_path), exist_ok=True)
        if not os.path.exists(self._baseline_path):
            baseline = {
                "admin": {"hour_min": 8, "hour_max": 20, "common_ips": ["127.0.0.1", "10.0.0.0/8"]},
            }
            with open(self._baseline_path, "w") as f:
                json.dump(baseline, f)

    def _scan(self) -> None:
        if not os.path.exists(self.auth_log):
            return
        try:
            with open(self.auth_log) as f:
                f.seek(self._last_pos)
                lines = f.readlines()
                self._last_pos = f.tell()
        except (PermissionError, OSError):
            return
        for line in lines:
            m = self._FAILED_RE.search(line)
            if m:
                user = m.group(1)
                ip = m.group(2)
                self._fail_window[user].append(time.time())
                window = [t for t in self._fail_window[user] if time.time() - t < 60]
                if len(window) >= 5:
                    self.emit(
                        EventType.SENSOR_BEHAVIOR_DRIFT,
                        {"user": user, "ip": ip, "fails_in_60s": len(window), "reason": "brute_force"},
                        severity="high",
                        tags=["behavior", "brute_force"],
                    )
            m = self._SUDO_RE.search(line)
            if m and "incorrect password" in line.lower():
                user = m.group(1)
                self.emit(
                    EventType.SENSOR_BEHAVIOR_DRIFT,
                    {"user": user, "reason": "sudo_failure"},
                    severity="medium",
                    tags=["behavior", "privesc"],
                )

    def compute_drift(self, user: str = "admin") -> float:
        """Calcula drift score 0-1 face à baseline."""
        try:
            with open(self._baseline_path) as f:
                baseline = json.load(f)
            ub = baseline.get(user, {})
        except Exception:
            ub = {}
        hour = time.localtime().tm_hour
        h_min = ub.get("hour_min", 8)
        h_max = ub.get("hour_max", 20)
        if h_min <= hour <= h_max:
            hour_drift = 0.0
        else:
            hour_drift = 0.7
        return hour_drift

    def start(self) -> None:
        super().start()
        self.safe_run_forever(self.interval, self._scan, name="sensor-behavior")

    def stop(self) -> None:
        super().stop()
