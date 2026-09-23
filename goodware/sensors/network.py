"""
Goodware v3.0 - Network sensor (psutil-based).
"""
from __future__ import annotations

from typing import Dict, Set, Tuple

import psutil

from goodware.core.events import EventType
from .base import BaseSensor


class NetworkSensor(BaseSensor):
    """Inventário de sockets; deteta listeners novos e conexões anómalas."""

    def __init__(self, name: str, config) -> None:
        super().__init__(name, config)
        self.interval = config.get("sensors.network.scan_interval_sec", 10)
        self.monitor_ports = set(config.get("sensors.network.monitor_ports", [22, 80, 443, 3389, 4444, 5555, 6666, 8080, 8443, 9001]))
        self._known_listeners: Set[Tuple[str, int]] = set()
        self._pid_conn_count: Dict[int, int] = {}

    def _scan(self) -> None:
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return
        listeners = []
        pid_count: Dict[int, int] = {}
        for c in conns:
            if not c.laddr:
                continue
            ip, port = c.laddr.ip, c.laddr.port
            if c.status == "LISTEN":
                listeners.append((ip, port, c.pid))
            if c.pid is not None:
                pid_count[c.pid] = pid_count.get(c.pid, 0) + 1
        # new listeners
        for ip, port, pid in listeners:
            key = (ip, port)
            if key in self._known_listeners:
                continue
            self._known_listeners.add(key)
            if port in self.monitor_ports:
                sev = "medium"
            elif port < 1024:
                sev = "high"
            else:
                sev = "medium"
            self.emit(
                EventType.SENSOR_NETWORK_ANOMALY,
                {"ip": ip, "port": port, "pid": pid, "reason": "new_listener"},
                severity=sev,
                tags=["network", "listener"],
            )
        # excessive connections from one pid
        for pid, count in pid_count.items():
            prev = self._pid_conn_count.get(pid, 0)
            if count > 50 and count > prev:
                self.emit(
                    EventType.SENSOR_NETWORK_ANOMALY,
                    {"pid": pid, "count": count, "reason": "excessive_connections"},
                    severity="high",
                    tags=["network", "flood"],
                )
            self._pid_conn_count[pid] = count

    def start(self) -> None:
        super().start()
        self.safe_run_forever(self.interval, self._scan, name="sensor-network")

    def stop(self) -> None:
        super().stop()
