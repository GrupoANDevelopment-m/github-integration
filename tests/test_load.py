"""
Goodware v3.0 — load, robustness and cryptographic regression tests.
These tests must fail on unexpected exceptions; they must not convert failures into skips.
"""
from __future__ import annotations

import logging
import random
import time
import unittest

import numpy as np

log = logging.getLogger("goodware.tests.load")


class LoadTestCase(unittest.TestCase):
    def test_pqc_throughput(self):
        """Measure real PQC round trips; skip only when liboqs is unavailable."""
        try:
            from goodware.crypto.real_pqc import RealPQC
        except ImportError as exc:
            self.skipTest(f"RealPQC unavailable: {exc}")

        pqc = RealPQC()
        if not pqc.is_real():
            self.skipTest("liboqs not available")

        samples = []
        for _ in range(50):
            start = time.perf_counter()
            public_key, secret_key, _algorithm = pqc.kem_keypair()
            ciphertext, shared_enc = pqc.kem_encaps(public_key)
            shared_dec = pqc.kem_decaps(secret_key, ciphertext)
            samples.append(time.perf_counter() - start)
            self.assertEqual(shared_enc, shared_dec)

        ordered = sorted(samples)
        p95 = ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]
        throughput = len(samples) / sum(samples)
        log.info("PQC KEM roundtrip: n=%d throughput=%.2f ops/s p95=%.6fs",
                 len(samples), throughput, p95)
        self.assertGreater(throughput, 0)
        self.assertGreater(p95, 0)

    def test_predictor_serial(self):
        """Call the real public predictor API repeatedly and verify its contract."""
        from goodware.prediction.threat_predictor import ThreatPredictor
        from goodware.core.config import GoodwareConfig

        predictor = ThreatPredictor("tp-load-test", GoodwareConfig())
        results = [predictor.predict() for _ in range(10)]
        self.assertEqual(len(results), 10)
        for result in results:
            self.assertIsInstance(result, dict)
            self.assertIn("threat_type", result)
            self.assertIn("confidence", result)
            self.assertIn("risk", result)
            self.assertGreaterEqual(result["confidence"], 0.0)
            self.assertLessEqual(result["confidence"], 1.0)
            self.assertGreaterEqual(result["risk"], 0.0)
            self.assertLessEqual(result["risk"], 1.0)


class ChaosTestCase(unittest.TestCase):
    def test_feature_extraction_is_deterministic_across_random_seeds(self):
        from goodware.prediction.threat_predictor import ThreatPredictor
        from goodware.core.config import GoodwareConfig

        predictor = ThreatPredictor("tp-determinism-test", GoodwareConfig())
        predictor.feature_count = 8
        events = [{"type": "network_connection", "severity": "high"},
                  {"type": "process_start", "severity": "medium"}]
        outputs = []
        for seed in (0, 42, 100, 999):
            random.seed(seed)
            outputs.append(predictor._extract_features(events))
        for output in outputs[1:]:
            np.testing.assert_array_equal(outputs[0], output)

    def test_malformed_events_do_not_crash_feature_extraction(self):
        from goodware.prediction.threat_predictor import ThreatPredictor
        from goodware.core.config import GoodwareConfig

        predictor = ThreatPredictor("tp-malformed-test", GoodwareConfig())
        predictor.feature_count = 8
        result = predictor._extract_features([{}, {"type": None}, None, "bad-row", {"severity": "unknown"}])
        self.assertEqual(result.shape, (8,))
        self.assertTrue(np.isfinite(result).all())


class PropertyTestCase(unittest.TestCase):
    def test_kem_decaps_recovers_correctly(self):
        from goodware.crypto.real_pqc import RealPQC

        pqc = RealPQC()
        if not pqc.is_real():
            self.skipTest("liboqs not available")
        for i in range(10):
            public_key, secret_key, _algorithm = pqc.kem_keypair()
            ciphertext, shared_enc = pqc.kem_encaps(public_key)
            shared_dec = pqc.kem_decaps(secret_key, ciphertext)
            self.assertEqual(shared_enc, shared_dec, f"Iteration {i}")

    def test_sig_roundtrip_for_any_message(self):
        from goodware.crypto.real_pqc import RealPQC

        pqc = RealPQC()
        if not pqc.is_real():
            self.skipTest("liboqs not available")
        public_key, secret_key, _algorithm = pqc.sig_keypair()
        messages = [b"", b"a", b"x" * 1000, bytes(range(256)), b"\x00" * 100]
        for message in messages:
            signature = pqc.sig_sign(secret_key, message)
            self.assertTrue(pqc.sig_verify(public_key, message, signature), f"len={len(message)}")
            self.assertFalse(pqc.sig_verify(public_key, message + b"x", signature))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
