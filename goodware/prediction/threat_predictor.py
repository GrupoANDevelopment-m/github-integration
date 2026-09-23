"""Threat predictor: predicts attacks before they occur."""
from __future__ import annotations
import os
import time
import threading
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import joblib


class ThreatPredictor:
    THREAT_TYPES = ["normal", "scan", "brute_force", "ransomware_precursor", "lateral_movement"]

    def __init__(self, name: str, config):
        self.name = name
        self.config = config
        self.engine = None
        self._running = False
        self._thread = None
        self.model_dir = config.get("prediction.model_dir", "models")
        os.makedirs(self.model_dir, exist_ok=True)
        self.model = None
        self.iso_forest = None
        self._features = None
        self._labels = None
        self._ensure_synthetic_data()
        self.train()

    def attach(self, engine):
        self.engine = engine
        self.logger = engine.logger

    def _ensure_synthetic_data(self):
        np.random.seed(42)
        n_per_class = 50
        all_X, all_y = [], []
        for idx, tt in enumerate(self.THREAT_TYPES):
            if tt == "normal":
                X = np.random.normal(0, 0.5, (n_per_class, 8))
            elif tt == "scan":
                X = np.random.normal(2, 1, (n_per_class, 8))
            elif tt == "brute_force":
                X = np.random.normal(4, 1.2, (n_per_class, 8))
            elif tt == "ransomware_precursor":
                X = np.random.normal(6, 1.5, (n_per_class, 8))
            else:
                X = np.random.normal(3, 0.8, (n_per_class, 8))
            all_X.append(X)
            all_y.extend([idx] * n_per_class)
        self._features = np.vstack(all_X).astype(np.float32)
        self._labels = np.array(all_y)

    def train(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=8)
        self.model.fit(self._features, self._labels)
        self.iso_forest = IsolationForest(contamination=0.1, random_state=42)
        self.iso_forest.fit(self._features)
        try:
            joblib.dump(self.model, os.path.join(self.model_dir, "threat_predictor.joblib"))
        except Exception:
            pass
        return self.model

    def _extract_features(self, events):
        if not events:
            return np.zeros(8, dtype=np.float32)
        sev_w = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        sevs = [sev_w.get(e.get("severity", "info"), 0) for e in events[-20:]]
        types = [hash(e.get("type", "")) % 100 for e in events[-20:]]
        return np.array([
            len(events) / 100.0,
            np.mean(sevs) if sevs else 0,
            np.max(sevs) if sevs else 0,
            np.std(sevs) if sevs else 0,
            len(set(types)) / 20.0,
            np.mean(types) / 100.0 if types else 0,
            sum(1 for s in sevs if s >= 3),
            max(sevs) * (len(events) / 100.0),
        ], dtype=np.float32)

    def predict(self):
        events = self.engine.state.query_events(limit=100) if self.engine else []
        feats = self._extract_features(events).reshape(1, -1)
        try:
            proba = self.model.predict_proba(feats)[0]
            idx = int(np.argmax(proba))
            tt = self.THREAT_TYPES[idx]
            conf = float(proba[idx])
        except Exception:
            tt, conf = "normal", 0.5
        iso_score = float(self.iso_forest.decision_function(feats)[0])
        risk = min(1.0, max(0.0, (1 - iso_score) / 2 + conf / 2))
        importance = self.model.feature_importances_ if hasattr(self.model, "feature_importances_") else np.zeros(8)
        top_idx = int(np.argmax(importance))
        explanation = f"top feature #{top_idx} (imp={importance[top_idx]:.2f}), iso={iso_score:.2f}"
        return {"threat_type": tt, "confidence": conf, "risk": risk, "explanation": explanation}

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="threat-predictor")
        self._thread.start()

    def _loop(self):
        interval = self.config.get("prediction.horizon_hours", 24) * 60
        interval = min(interval, 60)  # cap at 60s for demo
        while self._running:
            try:
                pred = self.predict()
                if pred["confidence"] >= 0.6:
                    from goodware.core.events import EventType, Severity
                    self.engine.emit(
                        EventType.PREDICTION_THREAT,
                        pred,
                        severity=Severity.HIGH if pred["risk"] > 0.7 else Severity.MEDIUM,
                        source=self.name,
                        tags=["prediction", pred["threat_type"]],
                    )
                    self.engine.state.add_prediction(
                        f"pred-{int(time.time())}",
                        self.config.get("prediction.horizon_hours", 24),
                        pred["threat_type"],
                        pred["confidence"],
                        pred["risk"],
                        pred["explanation"],
                    )
            except Exception as e:
                self.logger.error(f"threat predictor: {e}")
            time.sleep(interval)

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running, "model": "RandomForest", "classes": self.THREAT_TYPES}
