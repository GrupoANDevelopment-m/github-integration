"""Anomaly forecasting: time-series + trends."""
from __future__ import annotations
import time
import threading
import numpy as np


class AnomalyForecast:
    def __init__(self, name: str, config):
        self.name = name
        self.config = config
        self.engine = None
        self._running = False
        self._thread = None
        self._history = []

    def attach(self, engine):
        self.engine = engine
        self.logger = engine.logger

    def _ingest(self):
        events = self.engine.state.query_events(limit=200) if self.engine else []
        sev_w = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        scores = [sev_w.get(e.get("severity", "info"), 0) for e in events]
        self._history = scores[::-1]  # oldest first
        if not self._history:
            np.random.seed(0)
            self._history = list(np.random.normal(0.5, 0.3, 50).clip(0, 4))

    def forecast(self, horizon_h: float = 1.0):
        self._ingest()
        arr = np.array(self._history[-50:], dtype=float)
        if len(arr) < 5:
            return {"metric": "severity", "current": 0.0, "predicted": 0.0, "confidence": 0.0, "horizon": horizon_h}
        # exponential smoothing
        alpha = 0.3
        s = arr[0]
        for v in arr[1:]:
            s = alpha * v + (1 - alpha) * s
        predicted = s
        # trend
        if len(arr) >= 10:
            x = np.arange(len(arr))
            slope = np.polyfit(x, arr, 1)[0]
            predicted = s + slope * horizon_h * 10
        std = float(np.std(arr))
        confidence = min(1.0, len(arr) / 50.0)
        risk = min(1.0, predicted / 4.0)
        return {
            "metric": "severity_score",
            "current": float(arr[-1]),
            "predicted": float(predicted),
            "std": float(std),
            "confidence": float(confidence),
            "risk": float(risk),
            "horizon": float(horizon_h),
            "trend": "rising" if predicted > arr[-1] else "falling",
        }

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="anomaly-forecast")
        self._thread.start()

    def _loop(self):
        while self._running:
            try:
                f = self.forecast(1.0)
                if f["risk"] > 0.6 and f["confidence"] > 0.5:
                    from goodware.core.events import EventType, Severity
                    self.engine.emit(
                        EventType.PREDICTION_ANOMALY,
                        f,
                        severity=Severity.MEDIUM,
                        source=self.name,
                    )
            except Exception as e:
                self.logger.error(f"anomaly forecast: {e}")
            time.sleep(60)

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running, "history_size": len(self._history)}
