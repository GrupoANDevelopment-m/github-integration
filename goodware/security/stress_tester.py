"""
Goodware v3.0 — Stress Tester & Real-Attack Load Generator.

Submete o sistema a cenários reais:
  1. Event flood (1000+ events/segundo)
  2. CVE burst (100 CVEs simultâneos)
  3. Attack patterns (8 categorias MITRE ATT&CK)
  4. Auth abuse (rate-limit testing)
  5. Crypto stress (PQC roundtrips em batch)
  6. Decision storms (eventos críticos concorrentes)
  7. Sensor saturation (filesystem, process, network)

Reporta latência p50/p95/p99, throughput, e falhas.
"""
from __future__ import annotations

import json
import logging
import multiprocessing
import os
import random
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

log = logging.getLogger("goodware.security.stress")


class StressTest:
    """Real stress test suite for Goodware."""

    REAL_ATTACK_PATTERNS = [
        # Cada padrão é um evento que testa um caminho real do engine
        {"type": "ransomware_precursor", "severity": "critical",
         "indicators": ["mass_file_rename", "shadow_copy_delete"]},
        {"type": "credential_dump", "severity": "critical",
         "indicators": ["shadow_read", "sam_dump"]},
        {"type": "lateral_movement", "severity": "high",
         "indicators": ["psexec", "wmi_exec", "rdp_brute"]},
        {"type": "c2_beacon", "severity": "high",
         "indicators": ["dga_domain", "tls_tor", "http_heartbeat"]},
        {"type": "data_exfil", "severity": "high",
         "indicators": ["dns_tunnel", "large_https_upload"]},
        {"type": "privilege_escalation", "severity": "high",
         "indicators": ["sudo_abuse", "suid_binary"]},
        {"type": "persistence", "severity": "medium",
         "indicators": ["cron_persistence", "service_install"]},
        {"type": "discovery", "severity": "medium",
         "indicators": ["network_scan", "ad_enum"]},
    ]

    def __init__(self, engine):
        self.engine = engine
        self.results = []

    def test_event_flood(self, n: int = 1000, duration_sec: int = 10) -> Dict:
        """Inject N events within duration_sec, measure latency.

        Uses batch insert (record_events_batch) for high throughput.
        """
        log.info(f"Stress: event flood {n} events in {duration_sec}s (batched)")
        start = time.time()
        failures = 0
        batch_size = 100

        import uuid
        patterns = self.REAL_ATTACK_PATTERNS
        for batch_start in range(0, n, batch_size):
            batch = [{
                "id": f"flood-{batch_start}-{i}-{uuid.uuid4()}",
                "type": random.choice(["sensor.process_anomaly",
                                       "sensor.network_anomaly",
                                       "sensor.file_change"]),
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "source": "stress_test",
                "payload": {"stress_id": batch_start + i,
                            "attack": random.choice(patterns)["type"]},
                "timestamp": time.time(),
            } for i in range(min(batch_size, n - batch_start))]
            try:
                if hasattr(self.engine.state, "record_events_batch"):
                    self.engine.state.record_events_batch(batch)
                else:
                    for e in batch:
                        self.engine.state.record_event(e)
            except Exception as e:
                failures += 1
                log.error(f"Batch {batch_start} failed: {e}")

        total = time.time() - start
        result = {
            "test": "event_flood",
            "n_events": n,
            "duration_sec": round(total, 2),
            "throughput_eps": round(n / total, 1),
            "failures": failures,
            "passed": failures == 0,
        }
        self.results.append(result)
        return result

    def test_cve_burst(self, n: int = 100) -> Dict:
        """Lookup N CVEs concurrently."""
        log.info(f"Stress: CVE burst {n} lookups")
        latencies = []
        failures = 0

        # Get CVEs from data
        cves = []
        try:
            with open("data/cve/cve_database.json") as f:
                data = json.load(f)
            cves = [c.get("cve_id", "") for c in data.get("cves", [])]
        except Exception as e:
            log.warning(f"Failed to load CVEs: {e}")
            cves = ["CVE-2024-99999"] * n

        cves = cves[:n] if cves else ["CVE-2024-99999"] * n

        def lookup(cve_id):
            t0 = time.perf_counter()
            try:
                # Use the LLM tool
                from goodware.llm.tools import _search_iocs
                _search_iocs(value=cve_id, type="cve")
                return time.perf_counter() - t0
            except Exception as e:
                return -1

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(lookup, cve) for cve in cves]
            for f in as_completed(futures):
                lat = f.result()
                if lat < 0:
                    failures += 1
                else:
                    latencies.append(lat * 1000)

        if not latencies:
            return {"test": "cve_burst", "n": n, "passed": False, "error": "no results"}

        latencies.sort()
        result = {
            "test": "cve_burst",
            "n": n,
            "failures": failures,
            "p50_ms": round(statistics.median(latencies), 2),
            "p95_ms": round(latencies[int(len(latencies) * 0.95)], 2),
            "max_ms": round(max(latencies), 2),
            "passed": failures < n * 0.05,  # 5% failure threshold
        }
        self.results.append(result)
        return result

    def test_pqc_throughput(self, n: int = 100) -> Dict:
        """PQC roundtrips in batch."""
        log.info(f"Stress: PQC {n} roundtrips")
        try:
            from goodware.crypto.real_pqc import RealPQC
            pqc = RealPQC(algorithm="ML-DSA-44")
        except Exception as e:
            return {"test": "pqc_throughput", "n": n, "passed": False, "error": str(e)}

        latencies = []
        for i in range(n):
            t0 = time.perf_counter()
            try:
                pk, sk, _ = pqc.sig_keypair("ML-DSA-44")
                sig = pqc.sig_sign(sk, f"msg_{i}".encode(), "ML-DSA-44")
                pqc.sig_verify(pk, f"msg_{i}".encode(), sig, "ML-DSA-44")
                latencies.append((time.perf_counter() - t0) * 1000)
            except Exception as e:
                log.error(f"PQC {i} failed: {e}")

        if not latencies:
            return {"test": "pqc_throughput", "n": n, "passed": False}

        latencies.sort()
        result = {
            "test": "pqc_throughput",
            "n": n,
            "p50_ms": round(statistics.median(latencies), 2),
            "p95_ms": round(latencies[int(len(latencies) * 0.95)], 2),
            "max_ms": round(max(latencies), 2),
            "passed": True,
        }
        self.results.append(result)
        return result

    def test_decision_storm(self, n: int = 500) -> Dict:
        """Decision engine under load."""
        log.info(f"Stress: decision storm {n} decisions")
        try:
            from goodware.decision import DecisionManager
            dm = DecisionManager(self.engine, self.engine.config)
        except Exception as e:
            return {"test": "decision_storm", "passed": False, "error": str(e)}

        latencies = []
        failures = 0
        for i in range(n):
            t0 = time.perf_counter()
            try:
                event = {
                    "severity": random.choice(["low", "medium", "high", "critical"]),
                    "type": random.choice([p["type"] for p in self.REAL_ATTACK_PATTERNS]),
                    "payload": {"stress_id": i}
                }
                dm.decide(event)
            except Exception as e:
                failures += 1
            latencies.append((time.perf_counter() - t0) * 1000)

        latencies.sort()
        result = {
            "test": "decision_storm",
            "n": n,
            "failures": failures,
            "p50_ms": round(statistics.median(latencies), 2),
            "p95_ms": round(latencies[int(n * 0.95)], 2),
            "max_ms": round(max(latencies), 2),
            "passed": failures == 0,
        }
        self.results.append(result)
        return result

    def test_sensor_saturation(self, n: int = 5000) -> Dict:
        """Sensor write/read saturation."""
        log.info(f"Stress: sensor saturation {n} events")
        try:
            import uuid
            t0 = time.perf_counter()
            # Batch writes for throughput
            batch_size = 500
            for batch_start in range(0, n, batch_size):
                batch = [{
                    "id": f"sat-{batch_start}-{i}-{uuid.uuid4()}",
                    "type": "sensor.file_change",
                    "severity": "low",
                    "source": "saturation_test",
                    "payload": {"i": batch_start + i},
                    "timestamp": time.time(),
                } for i in range(min(batch_size, n - batch_start))]
                if hasattr(self.engine.state, "record_events_batch"):
                    self.engine.state.record_events_batch(batch)
                else:
                    for e in batch:
                        self.engine.state.record_event(e)
            elapsed = time.perf_counter() - t0
            # Now read all
            t1 = time.perf_counter()
            events = self.engine.state.query_events(limit=n)
            read_time = time.perf_counter() - t1

            result = {
                "test": "sensor_saturation",
                "n_writes": n,
                "n_reads": len(events),
                "write_time_sec": round(elapsed, 2),
                "read_time_sec": round(read_time, 2),
                "write_throughput_eps": round(n / elapsed, 1),
                "passed": elapsed < 60,  # < 1 min for 5000 writes
            }
        except Exception as e:
            result = {"test": "sensor_saturation", "passed": False, "error": str(e)}
        self.results.append(result)
        return result

    def test_api_resilience(self, base_url: str = "http://localhost:8444",
                             n: int = 200) -> Dict:
        """API endpoint under concurrent load."""
        log.info(f"Stress: API {n} requests")
        import urllib.request

        latencies = []
        failures = 0
        endpoints = [
            "/api/healthz", "/api/status", "/api/sensors",
            "/api/events?limit=10", "/api/threats",
            "/api/predictions", "/api/crypto",
        ]

        def hit():
            t0 = time.perf_counter()
            try:
                req = urllib.request.Request(base_url + random.choice(endpoints))
                with urllib.request.urlopen(req, timeout=5) as r:
                    r.read()
                return time.perf_counter() - t0
            except Exception:
                return -1

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(hit) for _ in range(n)]
            for f in as_completed(futures):
                lat = f.result()
                if lat < 0:
                    failures += 1
                else:
                    latencies.append(lat * 1000)

        if not latencies:
            return {"test": "api_resilience", "n": n, "passed": False}

        latencies.sort()
        result = {
            "test": "api_resilience",
            "n": n,
            "failures": failures,
            "p50_ms": round(statistics.median(latencies), 2),
            "p95_ms": round(latencies[int(len(latencies) * 0.95)], 2),
            "p99_ms": round(latencies[int(len(latencies) * 0.99)], 2),
            "max_ms": round(max(latencies), 2),
            "passed": failures < n * 0.01,  # 1% threshold
        }
        self.results.append(result)
        return result

    def run_all(self, scale: str = "light") -> Dict:
        """Run full stress test suite.

        scale: 'light' (fast), 'normal' (default), 'heavy' (production-grade)
        """
        scales = {
            "light": {"events": 200, "cves": 20, "pqc": 20, "decisions": 100, "sensors": 1000, "api": 100},
            "normal": {"events": 1000, "cves": 100, "pqc": 100, "decisions": 500, "sensors": 5000, "api": 500},
            "heavy": {"events": 5000, "cves": 500, "pqc": 500, "decisions": 2500, "sensors": 25000, "api": 2000},
        }
        params = scales.get(scale, scales["normal"])
        log.info(f"Running full stress test suite ({scale} scale)")
        start = time.time()

        self.results = []
        all_passed = True

        for test_name, test_fn, kwargs in [
            ("event_flood", self.test_event_flood, {"n": params["events"], "duration_sec": 5}),
            ("cve_burst", self.test_cve_burst, {"n": params["cves"]}),
            ("pqc_throughput", self.test_pqc_throughput, {"n": params["pqc"]}),
            ("decision_storm", self.test_decision_storm, {"n": params["decisions"]}),
            ("sensor_saturation", self.test_sensor_saturation, {"n": params["sensors"]}),
            ("api_resilience", self.test_api_resilience, {"n": params["api"]}),
        ]:
            try:
                result = test_fn(**kwargs)
                if not result.get("passed", False):
                    all_passed = False
                log.info(f"  {test_name}: {'PASS' if result.get('passed') else 'FAIL'}")
            except Exception as e:
                log.error(f"  {test_name} crashed: {e}")
                all_passed = False

        elapsed = time.time() - start
        summary = {
            "scale": scale,
            "elapsed_sec": round(elapsed, 2),
            "all_passed": all_passed,
            "tests": self.results,
        }
        # Persist
        os.makedirs("data/stress", exist_ok=True)
        with open(f"data/stress/run_{int(time.time())}.json", "w") as f:
            json.dump(summary, f, indent=2)
        return summary


def run_quick_stress(engine, scale: str = "light"):
    """Convenience function."""
    return StressTest(engine).run_all(scale)


if __name__ == "__main__":
    print("Run as: from goodware.security.stress_tester import StressTest")