"""Regression tests for honest ML inference contracts."""
import unittest

from goodware.prediction.threat_predictor import ThreatPredictor


class _ModelMustNotRun:
    def predict_proba(self, _features):
        raise AssertionError("incompatible model must not receive fabricated features")


class ThreatPredictorFeatureContractTests(unittest.TestCase):
    def test_network_flow_models_fail_closed_without_validated_feature_pipeline(self):
        for source in ("unsw_nb15", "nsl_kdd"):
            with self.subTest(source=source):
                predictor = ThreatPredictor.__new__(ThreatPredictor)
                predictor.model = _ModelMustNotRun()
                predictor.model_loaded = True
                predictor.model_source = source
                predictor.anomaly_source = source
                predictor.synthetic_fallback = False
                predictor.engine = None

                result = predictor.predict()

                self.assertEqual(result["threat_type"], "unavailable")
                self.assertEqual(result["confidence"], 0.0)
                self.assertEqual(result["risk"], 0.0)
                self.assertIn("feature_schema_mismatch", result["explanation"])
                self.assertEqual(result["model_source"], source)


if __name__ == "__main__":
    unittest.main()
