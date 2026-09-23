"""
Goodware v3.0 - Process sensor (psutil-based).
"""
from __future__ import annotations

import base64
import re
from typing import Dict, Set

import psutil

from goodware.core.events import EventType
from .base import BaseSensor


_B64_RE = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
_PIPE_SHELL = re.compile(r"(curl|wget)\s+[^\s|]+\s*\|\s*(sh|bash)")
_REVERSE_SHELL = re.compile(r"/dev/tcp/|nc\s+-e|ncat\s+-e|bash\s+-i")


class ProcessSensor(BaseSensor):
    """Detecta processos suspeitos por nome, path, payload ou árvore."""

    def __init__(self, name: str, config) -> None:
        super().__init__(name, config)
        self.interval = config.get("sensors.process.scan_interval_sec", 5)
        self.suspicious_names = set(
            config.get("sensors.process.suspicious_names", [
                "nc", "ncat", "netcat", "miner", "xmrig", "kdevtmpfsi",
                "cryptominer", "mirai", "tsunami", "mimikatz",
            ])
        )
        self.suspicious_paths = set(
            config.get("sensors.process.suspicious_paths", ["/tmp", "/dev/shm", "/var/tmp"])
        )
        self._known_pids: Set[int] = set()

    def _score(self, info: Dict) -> float:
        score = 0.0
        name = (info.get("name") or "").lower()
        exe = (info.get("exe") or "")
        cmdline = " ".join(info.get("cmdline") or [])

        if name in self.suspicious_names:
            score = max(score, 0.9)
        for sp in self.suspicious_paths:
            if sp in exe:
                score = max(score, 0.7)
                break
        if _B64_RE.search(cmdline):
            score = max(score, 0.8)
        if _PIPE_SHELL.search(cmdline):
            score = max(score, 0.85)
        if _REVERSE_SHELL.search(cmdline):
            score = max(score, 0.95)
        return score

    def _scan(self) -> None:
        try:
            current = psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "username", "create_time"]
            )
        except Exception:
            return
        for proc in current:
            try:
                info = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            pid = info.get("pid")
            score = self._score(info)
            if score >= 0.6 and pid not in self._known_pids:
                self._known_pids.add(pid)
                severity = "critical" if score >= 0.85 else "high"
                self.emit(
                    EventType.SENSOR_PROCESS_ANOMALY,
                    {
                        "pid": pid,
                        "name": info.get("name"),
                        "exe": info.get("exe"),
                        "cmdline": (info.get("cmdline") or [])[:6],
                        "user": info.get("username"),
                        "anomaly_score": round(score, 2),
                        "reason": "suspicious_pattern",
                    },
                    severity=severity,
                    tags=["process", "anomaly"],
                )
            elif pid in self._known_pids and score < 0.5:
                self._known_pids.discard(pid)
        # trim known set
        if len(self._known_pids) > 5000:
            self._known_pids = set(list(self._known_pids)[-2000:])

    def start(self) -> None:
        super().start()
        self.safe_run_forever(self.interval, self._scan, name="sensor-process")

    def stop(self) -> None:
        super().stop()
