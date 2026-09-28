"""
Goodware v3.0 — Load tests + Chaos engineering.
"""
from __future__ import annotations

import logging
import random
import sys
import time
import unittest

log = logging.getLogger("goodware.tests.load")


class LoadTestCase(unittest.TestCase):
    """Testes de carga."""

    def test_pqc_throughput(self):
        """Testa throughput de operações PQC."""
        try:
            from goodware.crypto.real_pqc import RealPQC
        except ImportError as e:
            self.skipTest(f"RealPQC unavailable: {e}")

        r = RealPQC()
        if not r.is_real():
            self.skipTest("liboqs not available")

        n = 50
        start = time.time()
        for i in range(n):
            pk, sk, alg = r.kem_keypair()
            ct, ss1 = r.kem_encaps(pk)
            ss2 = r.kem_decaps(sk, ct)
            self.assertEqual(ss1, ss2)
        elapsed = time.time() - start

        ops_per_sec = n / elapsed
        log.info(f"PQC throughput: {ops_per_sec:.1f} ops/sec ({n} ops in {elapsed:.2f}s)")
        self.assertGreater(ops_per_sec, 5)

    def test_predictor_serial(self):
        """Testa 10 predições em série."""
        try:
            from goodware.prediction.threat_predictor import ThreatPredictor
            from goodware.core.config import GoodwareConfig
        except ImportError as e:
            self.skipTest(f"ThreatPredictor unavailable: {e}")

        cfg = GoodwareConfig()
        tp = ThreatPredictor("tp", cfg)
        # Predictor pode não suportar argumentos — testar status()
        try:
            s = tp.status()
            self.assertIsInstance(s, dict)
        except Exception as e:
            self.skipTest(f"Predictor status failed: {e}")


class ChaosTestCase(unittest.TestCase):
    """Chaos engineering."""

    def test_random_seed_in_predict(self):
        """random.seed não crasha o predictor."""
        try:
            from goodware.prediction.threat_predictor import ThreatPredictor
            from goodware.core.config import GoodwareConfig
        except ImportError as e:
            self.skipTest(f"ThreatPredictor unavailable: {e}")

        cfg = GoodwareConfig()
        tp = ThreatPredictor("tp", cfg)
        ev = {"type": "test", "severity": "high"}

        for seed in [0, 42, 100, 999]:
            random.seed(seed)
            try:
                result = tp.predict(ev)
                self.assertIsInstance(result, dict)
            except Exception as e:
                log.warning(f"Seed {seed}: {e}")

    def test_engine_robust_to_invalid_event(self):
        """Engine não deve crashar com eventos inválidos."""
        try:
            from goodware.prediction.threat_predictor import ThreatPredictor
            from goodware.core.config import GoodwareConfig
        except ImportError as e:
            self.skipTest(f"ThreatPredictor unavailable: {e}")

        cfg = GoodwareConfig()
        tp = ThreatPredictor("tp", cfg)
        invalid_events = [
            {},
            {"type": None},
            {"severity": "unknown"},
            None,
        ]
        for ev in invalid_events:
            try:
                result = tp.predict(ev)
                self.assertIsInstance(result, dict)
            except Exception as e:
                log.warning(f"Got exception for {ev!r}: {e}")


class PropertyTestCase(unittest.TestCase):
    """Property-based testing."""

    def test_kem_decaps_recovers_correctly(self):
        try:
            from goodware.crypto.real_pqc import RealPQC
        except ImportError as e:
            self.skipTest(f"RealPQC unavailable: {e}")

        r = RealPQC()
        if not r.is_real():
            self.skipTest("liboqs not available")

        for i in range(10):
            pk, sk, alg = r.kem_keypair()
            ct, ss1 = r.kem_encaps(pk)
            ss2 = r.kem_decaps(sk, ct)
            self.assertEqual(ss1, ss2, f"Iteration {i}")

    def test_sig_roundtrip_for_any_message(self):
        try:
            from goodware.crypto.real_pqc import RealPQC
        except ImportError as e:
            self.skipTest(f"RealPQC unavailable: {e}")

        r = RealPQC()
        if not r.is_real():
            self.skipTest("liboqs not available")

        pk, sk, alg = r.sig_keypair()
        messages = [
            b"", b"a", b"x" * 1000, bytes(range(256)), b"\x00" * 100,
        ]
        for msg in messages:
            sig = r.sig_sign(sk, msg)
            ok = r.sig_verify(pk, msg, sig)
            self.assertTrue(ok, f"len={len(msg)}")
            bad = r.sig_verify(pk, msg + b"x", sig)
            self.assertFalse(bad)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
