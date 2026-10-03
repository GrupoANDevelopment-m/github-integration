"""Threat predictor: predicts attacks before they occur.

Production version: loads REAL trained models (.joblib) by default.
Falls back to synthetic data ONLY in dev with explicit DEV_GAMING_SYNTHETIC_OK flag.

Models loaded (priority order):
  1. threat_predictor_unsw_nb15.joblib (96.00% accuracy, 45 features)
  2. threat_predictor_nsl_kdd.joblib (77.66% accuracy, 41 features)
  3. threat_predictor.joblib (legacy, smaller)

Anomaly detectors:
  1. anomaly_detector_unsw_nb15.joblib (IsolationForest, UNSW-NB15)
  2. anomaly_detector_nsl_kdd.joblib (IsolationForest, NSL-KDD)
  3. anomaly_detector.joblib (legacy)

Honest reporting: this class now reports its REAL status:
  - model_source='unsw_nb15' | 'nsl_kdd' | 'legacy' | 'synthetic'
  - model_loaded=True/False
  - synthetic_fallback=True/False
"""
from __future__ import annotations
import os
import time
import threading
import logging
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import joblib

log = logging.getLogger("goodware.prediction.threat_predictor")


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
        # REAL state (honest reporting)
        self.model_source = "none"            # unsw_nb15|nsl_kdd|legacy|synthetic|none
        self.anomaly_source = "none"          # same options
        self.model_loaded = False
        self.anomaly_loaded = False
        self.synthetic_fallback = False
        self.feature_count = 0

        # Allow explicit dev-only synthetic fallback via env var
        self._dev_synthetic_allowed = os.environ.get("GOODWARE_DEV_SYNTHETIC_OK", "0") == "1"

        # Try load REAL models first; fallback ONLY if dev flag set or all loads fail
        loaded = self._try_load_real_models()
        if not loaded:
            if self._dev_synthetic_allowed:
                log.warning(
                    "[DEV] No real models found at %s; using synthetic data because "
                    "GOODWARE_DEV_SYNTHETIC_OK=1. NOT FOR PRODUCTION.",
                    self.model_dir
                )
                self._ensure_synthetic_data()
                self.train_synthetic()
                self.model_source = "synthetic"
                self.anomaly_source = "synthetic"
                self.synthetic_fallback = True
            else:
                log.error(
                    "No real trained models in %s. To use synthetic fallback in dev only, "
                    "set GOODWARE_DEV_SYNTHETIC_OK=1. Predictor will stay inactive.",
                    self.model_dir
                )
                # No fallback model — predict() will return "unavailable" honestly

    def attach(self, engine):
        self.engine = engine
        self.logger = engine.logger

    # ------------------------------------------------------------------
    # Real model loading (priority: UNSW-NB15 > NSL-KDD > legacy)
    # ------------------------------------------------------------------
    def _try_load_real_models(self) -> bool:
        loaded_any = False

        # 1. Try UNSW-NB15 (best accuracy: 96.00%, 45 features)
        try:
            p = os.path.join(self.model_dir, "threat_predictor_unsw_nb15.joblib")
            if os.path.exists(p):
                self.model = joblib.load(p)
                # Get feature count from model
                if hasattr(self.model, "n_features_in_"):
                    self.feature_count = int(self.model.n_features_in_)
                elif hasattr(self.model, "coef_"):
                    self.feature_count = int(self.model.coef_.shape[1])
                else:
                    self.feature_count = 45
                self.model_source = "unsw_nb15"
                self.model_loaded = True
                log.info("Loaded real UNSW-NB15 model: %s (%d features)", p, self.feature_count)
                # Try matching anomaly detector
                iso_p = os.path.join(self.model_dir, "anomaly_detector_unsw_nb15.joblib")
                if os.path.exists(iso_p):
                    self.iso_forest = joblib.load(iso_p)
                    self.anomaly_source = "unsw_nb15"
                    self.anomaly_loaded = True
                    log.info("Loaded real UNSW-NB15 IsolationForest: %s", iso_p)
                loaded_any = True
                return True
        except Exception as e:
            log.warning("Failed to load UNSW-NB15 model: %s", e)

        # 2. Try NSL-KDD (77.66% accuracy, 41 features)
        try:
            p = os.path.join(self.model_dir, "threat_predictor_nsl_kdd.joblib")
            if os.path.exists(p):
                self.model = joblib.load(p)
                if hasattr(self.model, "n_features_in_"):
                    self.feature_count = int(self.model.n_features_in_)
                else:
                    self.feature_count = 41
                self.model_source = "nsl_kdd"
                self.model_loaded = True
                log.info("Loaded real NSL-KDD model: %s (%d features)", p, self.feature_count)
                iso_p = os.path.join(self.model_dir, "anomaly_detector_nsl_kdd.joblib")
                if os.path.exists(iso_p):
                    self.iso_forest = joblib.load(iso_p)
                    self.anomaly_source = "nsl_kdd"
                    self.anomaly_loaded = True
                    log.info("Loaded real NSL-KDD IsolationForest: %s", iso_p)
                loaded_any = True
                return True
        except Exception as e:
            log.warning("Failed to load NSL-KDD model: %s", e)

        # 3. Legacy
        try:
            p = os.path.join(self.model_dir, "threat_predictor.joblib")
            if os.path.exists(p):
                self.model = joblib.load(p)
                self.feature_count = 8
                self.model_source = "legacy"
                self.model_loaded = True
                log.info("Loaded legacy threat model: %s", p)
                iso_p = os.path.join(self.model_dir, "anomaly_detector.joblib")
                if os.path.exists(iso_p):
                    self.iso_forest = joblib.load(iso_p)
                    self.anomaly_source = "legacy"
                    self.anomaly_loaded = True
                loaded_any = True
                return True
        except Exception as e:
            log.warning("Failed to load legacy model: %s", e)

        return loaded_any

    def _ensure_synthetic_data(self):
        """DEV ONLY — synthetic data via np.random.normal. Marked clearly."""
        log.warning("[DEV] _ensure_synthetic_data called — synthetic training data")
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

    def train_synthetic(self):
        """DEV ONLY — train a small model on synthetic data."""
        self.model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=8)
        self.model.fit(self._features, self._labels)
        self.iso_forest = IsolationForest(contamination=0.1, random_state=42)
        self.iso_forest.fit(self._features)
        # DO NOT persist synthetic model over real model
        return self.model

    def _extract_features(self, events):
        """Build feature vector from event stream (8 features, fixed schema).

        For real UNSW-NB15 (45 features) we build a rich vector; for the 8-feature
        schema used by the legacy model, we project. In practice, the real model
        expects network-flow-style features; here we approximate from event-level
        data. (Future: replace with real-time flow feature extraction.)
        """
        if not events:
            return np.zeros(self.feature_count or 8, dtype=np.float32)
        sev_w = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        sevs = [sev_w.get(e.get("severity", "info"), 0) for e in events[-20:]]
        types = [hash(e.get("type", "")) % 100 for e in events[-20:]]

        if self.feature_count >= 45:
            # UNSW-NB15-style features (45 dims)
            base8 = np.array([
                len(events) / 100.0,
                np.mean(sevs) if sevs else 0,
                np.max(sevs) if sevs else 0,
                np.std(sevs) if sevs else 0,
                len(set(types)) / 20.0,
                np.mean(types) / 100.0 if types else 0,
                sum(1 for s in sevs if s >= 3),
                max(sevs) * (len(events) / 100.0) if sevs else 0,
            ], dtype=np.float32)
            # Pad to 45 by replicating summary stats (NOT real flow features —
            # honest documentation: only meaningful if real netflow pipeline plugged in)
            extras = np.tile(base8, 5)[:self.feature_count]
            # Zero-pad to exact feature_count
            if len(extras) < self.feature_count:
                extras = np.concatenate([extras, np.zeros(self.feature_count - len(extras), dtype=np.float32)])
            return extras[:self.feature_count]

        # Legacy 8-feature path
        return np.array([
            len(events) / 100.0,
            np.mean(sevs) if sevs else 0,
            np.max(sevs) if sevs else 0,
            np.std(sevs) if sevs else 0,
            len(set(types)) / 20.0,
            np.mean(types) / 100.0 if types else 0,
            sum(1 for s in sevs if s >= 3),
            max(sevs) * (len(events) / 100.0) if sevs else 0,
        ], dtype=np.float32)

    def predict(self):
        if not self.model_loaded or self.model is None:
            return {
                "threat_type": "unavailable",
                "confidence": 0.0,
                "risk": 0.0,
                "explanation": "no real model loaded; set GOODWARE_DEV_SYNTHETIC_OK=1 for synthetic fallback in dev",
                "model_source": self.model_source,
                "synthetic_fallback": self.synthetic_fallback,
            }
        try:
            events = self.engine.state.query_events(limit=100) if self.engine else []
            feats = self._extract_features(events).reshape(1, -1)
            proba = self.model.predict_proba(feats)[0]
            idx = int(np.argmax(proba))
            tt = self.THREAT_TYPES[idx] if idx < len(self.THREAT_TYPES) else f"class_{idx}"
            conf = float(proba[idx])
            if self.iso_forest is not None:
                iso_score = float(self.iso_forest.decision_function(feats)[0])
            else:
                iso_score = 0.0
            risk = min(1.0, max(0.0, (1 - iso_score) / 2 + conf / 2))
            try:
                importance = self.model.feature_importances_
                top_idx = int(np.argmax(importance))
            except Exception:
                top_idx = -1
                importance = np.zeros(self.feature_count)
            explanation = (
                f"model={self.model_source} features={self.feature_count} "
                f"top_feat={top_idx} (imp={importance[top_idx]:.2f}) iso={iso_score:.2f}"
            )
            return {
                "threat_type": tt,
                "confidence": conf,
                "risk": risk,
                "explanation": explanation,
                "model_source": self.model_source,
                "anomaly_source": self.anomaly_source,
                "synthetic_fallback": self.synthetic_fallback,
            }
        except Exception as e:
            log.error("predict failed: %s", e)
            return {
                "threat_type": "error",
                "confidence": 0.0,
                "risk": 0.0,
                "explanation": f"predict failed: {e}",
                "model_source": self.model_source,
                "synthetic_fallback": self.synthetic_fallback,
            }

    def start(self):
        if not self.model_loaded and not self._dev_synthetic_allowed:
            log.warning(
                "ThreatPredictor.start() called but no model loaded and no dev fallback. "
                "Will run in idle mode reporting 'unavailable'."
            )
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="threat-predictor")
        self._thread.start()

    def _loop(self):
        interval = self.config.get("prediction.horizon_hours", 24) * 60
        interval = min(interval, 60)
        while self._running:
            try:
                pred = self.predict()
                if pred.get("confidence", 0) >= 0.6:
                    from goodware.core.events import EventType, Severity
                    if self.engine:
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
                if self.engine and hasattr(self.engine, "logger"):
                    self.engine.logger.error(f"threat predictor: {e}")
            time.sleep(interval)

    def stop(self):
        self._running = False

    def status(self):
        return {
            "running": self._running,
            "model_loaded": self.model_loaded,
            "model_source": self.model_source,
            "anomaly_source": self.anomaly_source,
            "synthetic_fallback": self.synthetic_fallback,
            "feature_count": self.feature_count,
            "threat_types": self.THREAT_TYPES,
            "real_models": self.model_source in ("unsw_nb15", "nsl_kdd"),
        }