"""
Goodware v3.0 - Memory sensor.
"""
from __future__ import annotations

import os
import time
from typing import Dict

import psutil

from goodware.core.events import EventType
from .base import BaseSensor


class MemorySensor(BaseSensor):
    """Detecta consumo anormal e regiões rwx sem path."""

    def __init__(self, name: str, config) -> None:
        super().__init__(name, config)
        self.interval = 30
        self._rss_history: Dict[int, list] = {}

    def _scan(self) -> None:
        try:
            total_mem = psutil.virtual_memory().total
        except Exception:
            return
        for proc in psutil.process_iter(["pid", "name", "memory_info"]):
            try:
                info = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            rss = getattr(info["memory_info"], "rss", 0) if info.get("memory_info") else 0
            if rss > total_mem * 0.5:
                self.emit(
                    EventType.SENSOR_PROCESS_ANOMALY,
                    {"pid": info["pid"], "name": info["name"], "rss_mb": rss // (1024 * 1024), "reason": "memory_anomaly"},
                    severity="high",
                    tags=["memory", "anomaly"],
                )
            # track growth
            hist = self._rss_history.setdefault(info["pid"], [])
            hist.append((time.time(), rss))
            if len(hist) > 10:
                hist.pop(0)
            if len(hist) >= 5 and (hist[-1][1] - hist[0][1]) > 100 * 1024 * 1024:
                self.emit(
                    EventType.SENSOR_PROCESS_ANOMALY,
                    {"pid": info["pid"], "name": info["name"], "growth_mb": (hist[-1][1] - hist[0][1]) // (1024 * 1024), "reason": "memory_growth"},
                    severity="medium",
                    tags=["memory", "growth"],
                )
                self._rss_history.pop(info["pid"], None)
        # cleanup
        if len(self._rss_history) > 5000:
            for k in list(self._rss_history.keys())[:2000]:
                self._rss_history.pop(k, None)
        # check rwx regions of self
        try:
            maps = open(f"/proc/{os.getpid()}/maps").read()
            for line in maps.splitlines()[:50]:
                if line.startswith("rw") and "x" in line.split()[1] if len(line.split()) > 1 else False:
                    if not line.split()[-1].startswith(("/", "[", "lib")):
                        # anonymous rwx — could be shellcode
                        self.emit(
                            EventType.SENSOR_PROCESS_ANOMALY,
                            {"pid": os.getpid(), "region": line.split()[0], "reason": "rwx_anonymous"},
                            severity="critical",
                            tags=["memory", "rwx"],
                        )
                        break
        except Exception:
            pass

    def start(self) -> None:
        super().start()
        self.safe_run_forever(self.interval, self._scan, name="sensor-memory")

    def stop(self) -> None:
        super().stop()
