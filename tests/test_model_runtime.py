"""Runtime checks against the real NSL-KDD-trained model artifacts.

Run after scripts/train_nsl_kdd.py. No mocked estimator or synthetic training data is used.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from goodware.core.config import GoodwareConfig
from goodware.prediction.training.train_nsl_kdd import load_nsl_kdd
from goodware.prediction.threat_predictor import ThreatPredictor


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"
DATA_TEST = ROOT / "NSL_KDD" / "KDDTest+.txt"


class RealModelRuntimeTests(unittest.TestCase):
    def setUp(self):
        required = [
            "threat_predictor_nsl_kdd.joblib",
            "anomaly_detector_nsl_kdd.joblib",
            "scaler_nsl_kdd.joblib",
            "encoder_protocol_type.joblib",
            "encoder_service.joblib",
            "encoder_flag.joblib",
            "training_metadata_nsl_kdd.json",
        ]
        missing = [name for name in required if not (MODEL_DIR / name).is_file()]
        if missing or not DATA_TEST.is_file():
            self.fail(f"real-model prerequisites missing; artifacts={missing}, dataset={DATA_TEST.exists()}")
        self.temp = tempfile.TemporaryDirectory()
        self.model_dir = Path(self.temp.name)
        for name in required:
            shutil.copy2(MODEL_DIR / name, self.model_dir / name)
        config = GoodwareConfig.load()
        config.set("prediction.model_dir", str(self.model_dir))
        self.predictor = ThreatPredictor("real-model-runtime-test", config)
        self.df = load_nsl_kdd(str(DATA_TEST))

    def tearDown(self):
        self.temp.cleanup()

    def test_real_model_loads_and_predicts_from_dataset_schema(self):
        self.assertTrue(self.predictor.model_loaded)
        self.assertEqual(self.predictor.model_source, "nsl_kdd")
        self.assertFalse(self.predictor.synthetic_fallback)
        row = self.df.iloc[0].to_dict()
        flow = {
            key: (value.item() if hasattr(value, "item") else value)
            for key, value in row.items()
            if key not in {"label", "difficulty", "is_attack", "attack_category"}
        }
        result = self.predictor.predict_network_flow(flow)
        self.assertIn(result["threat_type"], {"normal", "attack"}, result)
        self.assertEqual(result["feature_count"], self.predictor.feature_count)
        self.assertFalse(result["synthetic_fallback"])
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)
        self.assertGreaterEqual(result["risk"], 0.0)
        self.assertLessEqual(result["risk"], 1.0)

    def test_missing_required_feature_fails_closed(self):
        row = self.df.iloc[0].to_dict()
        flow = {
            key: (value.item() if hasattr(value, "item") else value)
            for key, value in row.items()
            if key not in {"label", "difficulty", "is_attack", "attack_category", "src_bytes"}
        }
        result = self.predictor.predict_network_flow(flow)
        self.assertEqual(result["threat_type"], "unavailable")
        self.assertIn("missing_numeric_feature:src_bytes", result["explanation"])

    def test_unknown_category_fails_closed(self):
        row = self.df.iloc[0].to_dict()
        flow = {
            key: (value.item() if hasattr(value, "item") else value)
            for key, value in row.items()
            if key not in {"label", "difficulty", "is_attack", "attack_category"}
        }
        flow["protocol_type"] = "__unknown_category_for_regression_test__"
        result = self.predictor.predict_network_flow(flow)
        self.assertEqual(result["threat_type"], "unavailable")
        self.assertIn("unknown_category:protocol_type", result["explanation"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
