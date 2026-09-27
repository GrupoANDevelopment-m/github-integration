"""
Goodware v3.0 — Telemetry & Observability.

Coleta métricas e traces de uso do LLM:
- Latência por chamada
- Tokens consumidos
- Erros por tipo
- Tools mais usadas
- Sessions mais longas

Exporta para OpenTelemetry-compatible JSON.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.llm.telemetry")


TELEMETRY_FILE = Path("/workspace/goodware-v3/data/telemetry.json")


class TelemetryCollector:
    """Collector de métricas."""

    def __init__(self):
        self._path = TELEMETRY_FILE
        self._metrics = {
            "runs_total": 0,
            "tokens_in_total": 0,
            "tokens_out_total": 0,
            "errors_total": 0,
            "tool_calls_total": 0,
            "sessions_created_total": 0,
            "latency_p50_ms": 0,
            "latency_p99_ms": 0,
            "errors_by_type": defaultdict(int),
            "tools_used": defaultdict(int),
            "sessions_by_session": defaultdict(int),
            "runs_per_day": defaultdict(int),
            "last_run_ts": None,
        }
        self._latencies: List[float] = []
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                # Restaurar mas converter defaultdicts
                for k, v in data.items():
                    if isinstance(v, dict):
                        self._metrics[k] = defaultdict(int, v)
                    else:
                        self._metrics[k] = v
            except Exception as e:
                log.warning(f"Failed to load telemetry: {e}")

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Converter defaultdicts para dicts
            data = {}
            for k, v in self._metrics.items():
                if isinstance(v, defaultdict):
                    data[k] = dict(v)
                else:
                    data[k] = v
            self._path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            log.warning(f"Failed to save telemetry: {e}")

    def record_run(
        self,
        duration_ms: float,
        tokens_in: int = 0,
        tokens_out: int = 0,
        session_id: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._metrics["runs_total"] += 1
            self._metrics["tokens_in_total"] += tokens_in
            self._metrics["tokens_out_total"] += tokens_out
            self._metrics["last_run_ts"] = time.time()
            self._latencies.append(duration_ms)
            # Manter últimas 1000 latências
            if len(self._latencies) > 1000:
                self._latencies = self._latencies[-1000:]
            # Percentis
            if self._latencies:
                sorted_l = sorted(self._latencies)
                self._metrics["latency_p50_ms"] = sorted_l[len(sorted_l) // 2]
                self._metrics["latency_p99_ms"] = sorted_l[int(len(sorted_l) * 0.99)]
            # Por dia
            day = time.strftime("%Y-%m-%d")
            self._metrics["runs_per_day"][day] += 1
            if session_id:
                self._metrics["sessions_by_session"][session_id] += 1
            if error:
                self._metrics["errors_total"] += 1
                self._metrics["errors_by_type"][error] += 1
            self._save()

    def record_tool_call(self, tool_name: str) -> None:
        with self._lock:
            self._metrics["tool_calls_total"] += 1
            self._metrics["tools_used"][tool_name] += 1
            self._save()

    def record_session(self) -> None:
        with self._lock:
            self._metrics["sessions_created_total"] += 1
            self._save()

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            data = {}
            for k, v in self._metrics.items():
                if isinstance(v, defaultdict):
                    data[k] = dict(v)
                else:
                    data[k] = v
            return data

    def export_prometheus(self) -> str:
        """Exporta em formato Prometheus."""
        m = self.get_metrics()
        lines = []
        lines.append("# HELP goodware_llm_runs_total Total de runs do LLM")
        lines.append("# TYPE goodware_llm_runs_total counter")
        lines.append(f"goodware_llm_runs_total {m.get('runs_total', 0)}")
        lines.append("# HELP goodware_llm_tokens_in_total Tokens input totais")
        lines.append("# TYPE goodware_llm_tokens_in_total counter")
        lines.append(f"goodware_llm_tokens_in_total {m.get('tokens_in_total', 0)}")
        lines.append("# HELP goodware_llm_tokens_out_total Tokens output totais")
        lines.append("# TYPE goodware_llm_tokens_out_total counter")
        lines.append(f"goodware_llm_tokens_out_total {m.get('tokens_out_total', 0)}")
        lines.append("# HELP goodware_llm_errors_total Erros totais")
        lines.append("# TYPE goodware_llm_errors_total counter")
        lines.append(f"goodware_llm_errors_total {m.get('errors_total', 0)}")
        lines.append("# HELP goodware_llm_latency_p50_ms Latência percentil 50 (ms)")
        lines.append("# TYPE goodware_llm_latency_p50_ms gauge")
        lines.append(f"goodware_llm_latency_p50_ms {m.get('latency_p50_ms', 0)}")
        lines.append("# HELP goodware_llm_latency_p99_ms Latência percentil 99 (ms)")
        lines.append("# TYPE goodware_llm_latency_p99_ms gauge")
        lines.append(f"goodware_llm_latency_p99_ms {m.get('latency_p99_ms', 0)}")
        return "\n".join(lines)


_collector: Optional[TelemetryCollector] = None


def get_telemetry() -> TelemetryCollector:
    global _collector
    if _collector is None:
        _collector = TelemetryCollector()
    return _collector
