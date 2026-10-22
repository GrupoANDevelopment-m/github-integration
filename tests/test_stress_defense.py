"""
Goodware v3.0 — Stress + Defense layer tests.
"""
import os
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, ROOT)


class TestWAF(unittest.TestCase):
    def test_allows_clean_request(self):
        from goodware.security.defense import WAF
        waf = WAF()
        ok, reason = waf.check("/api/status", "", "", "Mozilla/5.0", "10.0.0.1")
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")

    def test_blocks_sql_injection(self):
        from goodware.security.defense import WAF
        waf = WAF()
        ok, reason = waf.check("/api/users", "id=1' OR '1'='1", "", "", "")
        self.assertFalse(ok)
        self.assertIn("sql_injection", reason)

    def test_blocks_xss(self):
        from goodware.security.defense import WAF
        waf = WAF()
        ok, reason = waf.check("/api/search", "q=<script>alert(1)</script>", "", "", "")
        self.assertFalse(ok)
        self.assertIn("xss", reason)

    def test_blocks_path_traversal(self):
        from goodware.security.defense import WAF
        waf = WAF()
        ok, reason = waf.check("/api/file", "path=../../../etc/passwd", "", "", "")
        self.assertFalse(ok)
        self.assertIn("path_traversal", reason)

    def test_blocks_command_injection(self):
        from goodware.security.defense import WAF
        waf = WAF()
        ok, reason = waf.check("/api/cmd", "exec=;rm -rf /", "", "", "")
        self.assertFalse(ok)
        self.assertIn("command_injection", reason)

    def test_blocks_ssrf(self):
        from goodware.security.defense import WAF
        waf = WAF()
        ok, reason = waf.check("/api/proxy", "url=http://127.0.0.1/admin", "", "", "")
        self.assertFalse(ok)
        self.assertIn("ssrf", reason)

    def test_blocks_suspicious_user_agent(self):
        from goodware.security.defense import WAF
        waf = WAF()
        ok, reason = waf.check("/api/users", "", "", "sqlmap/1.0", "")
        self.assertFalse(ok)
        self.assertIn("user_agent", reason)

    def test_stats(self):
        from goodware.security.defense import WAF
        waf = WAF()
        waf.check("/api/users", "id=1", "", "", "")
        waf.check("/api/status", "", "", "", "")
        waf.check("/api/x", "q=<script>alert(1)</script>", "", "", "")
        stats = waf.get_stats()
        self.assertEqual(stats["requests"], 3)
        self.assertGreater(stats["blocked"], 0)


class TestRateLimiter(unittest.TestCase):
    def test_basic_consume(self):
        from goodware.security.defense import TokenBucket
        bucket = TokenBucket(capacity=5, refill_rate=1.0)
        # Consume 5
        for _ in range(5):
            ok, _ = bucket.consume("ip1")
            self.assertTrue(ok)
        # 6th should fail
        ok, retry = bucket.consume("ip1")
        self.assertFalse(ok)
        self.assertGreater(retry, 0)

    def test_per_key_isolation(self):
        from goodware.security.defense import TokenBucket
        bucket = TokenBucket(capacity=2, refill_rate=0.1)
        bucket.consume("ip1")
        bucket.consume("ip1")
        ok1, _ = bucket.consume("ip1")
        ok2, _ = bucket.consume("ip2")
        self.assertFalse(ok1)  # ip1 exhausted
        self.assertTrue(ok2)   # ip2 fresh

    def test_refill(self):
        from goodware.security.defense import TokenBucket
        bucket = TokenBucket(capacity=2, refill_rate=100.0)  # fast refill
        bucket.consume("ip1")
        bucket.consume("ip1")
        ok, _ = bucket.consume("ip1")
        self.assertFalse(ok)
        time.sleep(0.05)  # 0.05s * 100 = 5 tokens refilled
        ok, _ = bucket.consume("ip1")
        self.assertTrue(ok)


class TestIPReputation(unittest.TestCase):
    def setUp(self):
        # Cria blocklist temporária
        os.makedirs("data", exist_ok=True)
        with open("data/blocklist.txt", "w") as f:
            f.write("# Test blocklist\n")
            f.write("10.10.10.0/24\n")
            f.write("192.168.99.42\n")

    def tearDown(self):
        try:
            os.remove("data/blocklist.txt")
        except FileNotFoundError:
            pass

    def test_blocks_static_ip(self):
        from goodware.security.defense import IPReputation
        rep = IPReputation()
        blocked, reason = rep.is_blocked("192.168.99.42")
        self.assertTrue(blocked)
        # CIDR normalization to /32 for single IP
        self.assertIn("static", reason)

    def test_blocks_cidr_range(self):
        from goodware.security.defense import IPReputation
        rep = IPReputation()
        blocked, reason = rep.is_blocked("10.10.10.50")
        self.assertTrue(blocked)
        self.assertIn("static_cidr", reason)

    def test_allows_clean_ip(self):
        from goodware.security.defense import IPReputation
        rep = IPReputation()
        blocked, _ = rep.is_blocked("8.8.8.8")
        self.assertFalse(blocked)

    def test_dynamic_ban(self):
        from goodware.security.defense import IPReputation
        rep = IPReputation()
        rep.ban("1.2.3.4", "test_ban", duration_sec=10)
        blocked, reason = rep.is_blocked("1.2.3.4")
        self.assertTrue(blocked)
        self.assertEqual(reason, "test_ban")

    def test_dynamic_ban_expiry(self):
        from goodware.security.defense import IPReputation
        rep = IPReputation()
        rep.ban("5.6.7.8", "short_ban", duration_sec=1)
        self.assertTrue(rep.is_blocked("5.6.7.8")[0])
        time.sleep(1.5)
        self.assertFalse(rep.is_blocked("5.6.7.8")[0])


class TestSlowLorisGuard(unittest.TestCase):
    def test_allows_under_limit(self):
        from goodware.security.defense import SlowLorisGuard
        guard = SlowLorisGuard(max_concurrent_per_ip=5)
        for _ in range(5):
            self.assertTrue(guard.connection_start("1.1.1.1"))
        # 6th denied
        self.assertFalse(guard.connection_start("1.1.1.1"))

    def test_connection_end(self):
        from goodware.security.defense import SlowLorisGuard
        guard = SlowLorisGuard(max_concurrent_per_ip=2)
        guard.connection_start("1.1.1.1")
        guard.connection_start("1.1.1.1")
        self.assertFalse(guard.connection_start("1.1.1.1"))
        guard.connection_end("1.1.1.1")
        self.assertTrue(guard.connection_start("1.1.1.1"))


class TestDefenseLayer(unittest.TestCase):
    def test_full_request_ok(self):
        from goodware.security.defense import DefenseLayer
        defense = DefenseLayer()
        ok, reason, meta = defense.check_request(
            "8.8.8.8", "/api/status", "", "", "Mozilla/5.0"
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")

    def test_blocks_malicious_request(self):
        from goodware.security.defense import DefenseLayer
        defense = DefenseLayer()
        ok, reason, meta = defense.check_request(
            "8.8.8.8", "/api/x", "id=1' OR '1'='1", "", "sqlmap/1.0"
        )
        self.assertFalse(ok)

    def test_rate_limiting(self):
        from goodware.security.defense import DefenseLayer
        defense = DefenseLayer({
            "rate_capacity": 3, "rate_refill": 0.01  # very slow
        })
        # 3 should pass
        for i in range(3):
            ok, _, _ = defense.check_request("9.9.9.9", "/api/x")
            self.assertTrue(ok)
        # 4th should fail
        ok, reason, _ = defense.check_request("9.9.9.9", "/api/x")
        self.assertFalse(ok)
        self.assertIn("rate", reason)


class TestStressTester(unittest.TestCase):
    def test_stress_test_creation(self):
        from goodware.security.stress_tester import StressTest
        # Just instantiate, don't run
        st = StressTest(None)
        self.assertEqual(len(st.REAL_ATTACK_PATTERNS), 8)

    def test_pattern_count(self):
        from goodware.security.stress_tester import StressTest
        st = StressTest(None)
        types = [p["type"] for p in st.REAL_ATTACK_PATTERNS]
        # Local generated workload labels; these are not live attack executions.
        self.assertIn("ransomware_precursor", types)
        self.assertIn("credential_dump", types)
        self.assertIn("lateral_movement", types)
        self.assertIn("c2_beacon", types)
        self.assertIn("data_exfil", types)
        self.assertIn("privilege_escalation", types)
        self.assertIn("persistence", types)
        self.assertIn("discovery", types)

    def test_pqc_verification_false_fails_benchmark(self):
        from goodware.security.stress_tester import StressTest
        with patch("goodware.crypto.real_pqc.RealPQC") as pqc_cls:
            pqc = pqc_cls.return_value
            pqc.sig_keypair.return_value = (b"pk", b"sk", "ML-DSA-44")
            pqc.sig_sign.return_value = b"signature"
            pqc.sig_verify.return_value = False
            result = StressTest(None).test_pqc_throughput(n=1)
        self.assertFalse(result["passed"])
        self.assertEqual(result["failures"], 1)
        self.assertEqual(result["successes"], 0)

    def test_missing_cve_dataset_does_not_use_synthetic_ids(self):
        from goodware.security.stress_tester import StressTest
        with patch("builtins.open", side_effect=FileNotFoundError("dataset missing")):
            result = StressTest(None).test_cve_burst(n=2)
        self.assertFalse(result["passed"])
        self.assertEqual(result["n"], 0)
        self.assertIn("real CVE dataset unavailable", result["error"])

    def test_event_flood_counts_missing_batch_writes(self):
        from goodware.security.stress_tester import StressTest
        state = SimpleNamespace(record_events_batch=lambda batch: 0)
        result = StressTest(SimpleNamespace(state=state)).test_event_flood(n=2)
        self.assertFalse(result["passed"])
        self.assertEqual(result["failures"], 2)
        self.assertEqual(result["n_events_written"], 0)

    def test_sensor_saturation_requires_persisted_events(self):
        from goodware.security.stress_tester import StressTest
        state = SimpleNamespace(
            record_events_batch=lambda batch: 0,
            query_events=lambda limit: [],
        )
        result = StressTest(SimpleNamespace(state=state)).test_sensor_saturation(n=2)
        self.assertFalse(result["passed"])
        self.assertEqual(result["n_writes_successful"], 0)
        self.assertEqual(result["n_generated_ids_verified"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)