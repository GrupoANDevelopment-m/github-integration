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
import hashlib
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
        # Real network-flow inference artifacts. Generic event summaries are not
        # silently coerced into a dataset feature vector.
        self.feature_columns = []
        self.feature_scaler = None
        self.feature_encoders = {}

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
                self._load_network_flow_artifacts("unsw_nb15")
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
                self._load_network_flow_artifacts("nsl_kdd")
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

    def _load_network_flow_artifacts(self, source: str) -> None:
        """Load the exact feature schema, encoders and scaler saved by training."""
        import json

        metadata_path = os.path.join(self.model_dir, f"training_metadata_{source}.json")
        if not os.path.isfile(metadata_path):
            log.warning("Network-flow inference disabled: missing metadata %s", metadata_path)
            return
        try:
            with open(metadata_path, "r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            columns = metadata.get("features")
            if not isinstance(columns, list) or not columns or not all(isinstance(x, str) for x in columns):
                raise ValueError("metadata features must be a non-empty list of names")
            encoders = {}
            category_names = ("proto", "service", "state") if source == "unsw_nb15" else ("protocol_type", "service", "flag")
            for name in category_names:
                prefix = "encoder_unsw_" if source == "unsw_nb15" else "encoder_"
                path = os.path.join(self.model_dir, f"{prefix}{name}.joblib")
                if os.path.isfile(path):
                    encoders[name] = joblib.load(path)
            if source == "nsl_kdd":
                scaler_path = os.path.join(self.model_dir, "scaler_nsl_kdd.joblib")
                if not os.path.isfile(scaler_path):
                    raise FileNotFoundError("missing scaler_nsl_kdd.joblib")
                self.feature_scaler = joblib.load(scaler_path)
                if not encoders.keys() >= {"protocol_type", "service", "flag"}:
                    raise FileNotFoundError("one or more NSL-KDD category encoders are missing")
            else:
                if not encoders.keys() >= {"proto", "service", "state"}:
                    raise FileNotFoundError("one or more UNSW-NB15 category encoders are missing")
            if len(columns) != self.feature_count:
                raise ValueError(f"metadata has {len(columns)} features but model expects {self.feature_count}")
            self.feature_columns = columns
            self.feature_encoders = encoders
            log.info("Loaded %s network-flow pipeline (%d features)", source, len(columns))
        except Exception as exc:
            self.feature_columns = []
            self.feature_scaler = None
            self.feature_encoders = {}
            log.warning("Network-flow inference disabled for %s: %s", source, exc)

    def predict_network_flow(self, flow: dict) -> dict:
        """Predict from one real flow matching the training dataset schema.

        Required numeric fields and categorical values are defined by the model's
        training metadata. Unknown categories, missing fields and invalid numbers
        fail closed; event summaries are never substituted for network-flow data.
        """
        unavailable = {
            "threat_type": "unavailable", "confidence": 0.0, "risk": 0.0,
            "model_source": self.model_source, "synthetic_fallback": self.synthetic_fallback,
        }
        if not isinstance(flow, dict):
            return {**unavailable, "explanation": "invalid_flow: expected a mapping"}
        if not self.model_loaded or self.model is None:
            return {**unavailable, "explanation": "no real trained model loaded"}
        if not self.feature_columns:
            return {**unavailable, "explanation": "validated_network_flow_pipeline_unavailable"}
        try:
            vector = []
            for column in self.feature_columns:
                if column.endswith("_enc"):
                    raw_name = column[:-4]
                    encoder = self.feature_encoders.get(raw_name)
                    if encoder is None or raw_name not in flow:
                        return {**unavailable, "explanation": f"missing_categorical_feature:{raw_name}"}
                    try:
                        encoded = int(encoder.transform([str(flow[raw_name])])[0])
                    except (ValueError, TypeError) as exc:
                        return {**unavailable, "explanation": f"unknown_category:{raw_name}:{exc}"}
                    vector.append(encoded)
                else:
                    if column not in flow:
                        return {**unavailable, "explanation": f"missing_numeric_feature:{column}"}
                    value = float(flow[column])
                    if not np.isfinite(value):
                        return {**unavailable, "explanation": f"non_finite_feature:{column}"}
                    vector.append(value)
            features = np.asarray(vector, dtype=np.float64).reshape(1, -1)
            if self.feature_scaler is not None:
                features = self.feature_scaler.transform(features)
            predicted = int(self.model.predict(features)[0])
            probabilities = self.model.predict_proba(features)[0] if hasattr(self.model, "predict_proba") else None
            if probabilities is not None:
                classes = list(getattr(self.model, "classes_", range(len(probabilities))))
                attack_idx = classes.index(1) if 1 in classes else int(np.argmax(probabilities))
                confidence = float(probabilities[attack_idx])
            else:
                confidence = 0.0
            if self.model_source in ("nsl_kdd", "unsw_nb15"):
                threat_type = "attack" if predicted == 1 else "normal"
            else:
                threat_type = self.THREAT_TYPES[predicted] if 0 <= predicted < len(self.THREAT_TYPES) else f"class_{predicted}"
            anomaly_score = None
            if self.iso_forest is not None:
                anomaly_score = float(self.iso_forest.decision_function(features)[0])
            risk = min(1.0, max(0.0, confidence if predicted == 1 else 1.0 - confidence))
            return {
                "threat_type": threat_type, "confidence": confidence, "risk": risk,
                "model_source": self.model_source, "anomaly_source": self.anomaly_source,
                "anomaly_score": anomaly_score, "feature_count": len(vector),
                "synthetic_fallback": False, "explanation": "prediction from validated network-flow feature schema",
            }
        except (ValueError, TypeError, KeyError) as exc:
            return {**unavailable, "explanation": f"invalid_flow_features:{exc}"}
        except Exception as exc:
            log.exception("network-flow prediction failed")
            return {**unavailable, "explanation": f"prediction_error:{type(exc).__name__}"}

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
        # Ignore malformed rows instead of letting a single bad event crash extraction.
        if not isinstance(events, (list, tuple)):
            events = []
        events = [e for e in events if isinstance(e, dict)]
        if not events:
            return np.zeros(self.feature_count or 8, dtype=np.float32)
        sev_w = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        recent = events[-20:]
        sevs = [sev_w.get(str(e.get("severity", "info")).lower(), 0) for e in recent]
        # Python's built-in hash is randomized per process; use a stable digest instead.
        types = [
            int.from_bytes(hashlib.sha256(str(e.get("type", "")).encode("utf-8")).digest()[:4], "big") % 100
            for e in recent
        ]

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
        # Real dataset models require a genuine flow payload; never fabricate
        # network-flow fields from generic process/event summaries.
        if self.model_source in ("unsw_nb15", "nsl_kdd"):
            events = self.engine.state.query_events(limit=100) if self.engine else []
            for event in reversed(events or []):
                if isinstance(event, dict):
                    flow = event.get("network_flow", event.get("flow"))
                    if isinstance(flow, dict):
                        return self.predict_network_flow(flow)
            return {
                "threat_type": "unavailable", "confidence": 0.0, "risk": 0.0,
                "explanation": (
                    f"network_flow_required: {self.model_source} needs a real flow payload "
                    "matching its training schema; generic event summaries are not compatible"
                ),
                "model_source": self.model_source, "anomaly_source": self.anomaly_source,
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