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
import math
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

    @staticmethod
    def _percentile(sorted_values: List[float], percentile: float) -> float:
        """Nearest-rank percentile for an already sorted non-empty sample."""
        if not sorted_values:
            raise ValueError("percentile requires at least one sample")
        rank = max(1, math.ceil(percentile * len(sorted_values)))
        return sorted_values[min(rank - 1, len(sorted_values) - 1)]

    def test_event_flood(self, n: int = 1000, duration_sec: int = 10) -> Dict:
        """Insert generated stress events and verify the number persisted."""
        log.info(f"Stress: event flood {n} generated events (target window {duration_sec}s)")
        start = time.perf_counter()
        failed_events = 0
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
                    written = self.engine.state.record_events_batch(batch)
                    failed_events += max(0, len(batch) - int(written or 0))
                else:
                    for event in batch:
                        try:
                            self.engine.state.record_event(event)
                        except Exception as exc:
                            failed_events += 1
                            log.error(f"Event {event['id']} failed: {exc}")
            except Exception as exc:
                failed_events += len(batch)
                log.error(f"Batch {batch_start} failed: {exc}")

        elapsed = max(time.perf_counter() - start, 1e-9)
        written_count = max(0, n - failed_events)
        result = {
            "test": "event_flood",
            "n_events_requested": n,
            "n_events_written": written_count,
            "duration_sec": round(elapsed, 4),
            "target_duration_sec": duration_sec,
            "throughput_eps": round(written_count / elapsed, 1),
            "failures": failed_events,
            "passed": n > 0 and failed_events == 0 and written_count == n,
        }
        self.results.append(result)
        return result

    def test_cve_burst(self, n: int = 100) -> Dict:
        """Benchmark CVE lookups using only the repository's real dataset."""
        log.info(f"Stress: CVE burst up to {n} real dataset lookups")
        latencies = []
        failures = 0

        try:
            with open("data/cve/cve_database.json", encoding="utf-8") as f:
                data = json.load(f)
            cves = [item.get("cve_id", "") for item in data.get("cves", [])
                    if isinstance(item, dict) and item.get("cve_id")]
        except Exception as exc:
            result = {
                "test": "cve_burst", "requested_n": n, "n": 0,
                "failures": 0, "passed": False,
                "error": f"real CVE dataset unavailable: {type(exc).__name__}: {exc}",
            }
            self.results.append(result)
            return result

        cves = cves[:n]
        if not cves:
            result = {
                "test": "cve_burst", "requested_n": n, "n": 0,
                "failures": 0, "passed": False,
                "error": "real CVE dataset contains no usable CVE IDs; synthetic fallback disabled",
            }
            self.results.append(result)
            return result

        def lookup(cve_id):
            t0 = time.perf_counter()
            try:
                from goodware.llm.tools import _lookup_cve
                result = _lookup_cve(query=cve_id)
                if not isinstance(result, dict) or result.get("error"):
                    return -1
                return time.perf_counter() - t0
            except Exception:
                return -1

        with ThreadPoolExecutor(max_workers=min(20, len(cves))) as ex:
            futures = [ex.submit(lookup, cve) for cve in cves]
            for future in as_completed(futures):
                latency = future.result()
                if latency < 0:
                    failures += 1
                else:
                    latencies.append(latency * 1000)

        if not latencies:
            result = {
                "test": "cve_burst", "requested_n": n, "n": len(cves),
                "failures": failures, "passed": False, "error": "no successful lookup results",
            }
        else:
            latencies.sort()
            result = {
                "test": "cve_burst",
                "requested_n": n,
                "n": len(cves),
                "successes": len(latencies),
                "failures": failures,
                "p50_ms": round(statistics.median(latencies), 2),
                "p95_ms": round(self._percentile(latencies, 0.95), 2),
                "p99_ms": round(self._percentile(latencies, 0.99), 2),
                "max_ms": round(max(latencies), 2),
                "passed": failures <= math.floor(len(cves) * 0.05),
            }
        self.results.append(result)
        return result

    def test_pqc_throughput(self, n: int = 100) -> Dict:
        """Benchmark ML-DSA keygen/sign/verify and fail on invalid signatures."""
        log.info(f"Stress: PQC ML-DSA-44 {n} keygen/sign/verify cycles")
        try:
            from goodware.crypto.real_pqc import RealPQC
            pqc = RealPQC(algorithm="ML-DSA-44")
        except Exception as exc:
            result = {"test": "pqc_throughput", "n": n, "passed": False, "error": str(exc)}
            self.results.append(result)
            return result

        latencies = []
        failures = 0
        start = time.perf_counter()
        for i in range(n):
            t0 = time.perf_counter()
            try:
                pk, sk, _ = pqc.sig_keypair("ML-DSA-44")
                message = f"msg_{i}".encode()
                signature = pqc.sig_sign(sk, message, "ML-DSA-44")
                verified = pqc.sig_verify(pk, message, signature, "ML-DSA-44")
                if not verified:
                    failures += 1
                    log.error(f"PQC verification returned false for iteration {i}")
            except Exception as exc:
                failures += 1
                log.error(f"PQC {i} failed: {exc}")
            finally:
                latencies.append((time.perf_counter() - t0) * 1000)

        elapsed = max(time.perf_counter() - start, 1e-9)
        latencies.sort()
        successes = max(0, n - failures)
        result = {
            "test": "pqc_throughput",
            "algorithm": "ML-DSA-44",
            "n_requested": n,
            "n_completed": len(latencies),
            "successes": successes,
            "failures": failures,
            "elapsed_sec": round(elapsed, 4),
            "throughput_ops_sec": round(successes / elapsed, 2),
            "p50_ms": round(statistics.median(latencies), 2) if latencies else None,
            "p95_ms": round(self._percentile(latencies, 0.95), 2) if latencies else None,
            "p99_ms": round(self._percentile(latencies, 0.99), 2) if latencies else None,
            "max_ms": round(max(latencies), 2) if latencies else None,
            "passed": n > 0 and failures == 0 and len(latencies) == n,
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
        """Measure write/read throughput and verify every generated event persisted."""
        log.info(f"Stress: sensor saturation {n} events")
        try:
            import uuid
            expected_ids = set()
            t0 = time.perf_counter()
            write_failures = 0
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
                expected_ids.update(event["id"] for event in batch)
                if hasattr(self.engine.state, "record_events_batch"):
                    written = self.engine.state.record_events_batch(batch)
                    write_failures += max(0, len(batch) - int(written or 0))
                else:
                    for event in batch:
                        try:
                            self.engine.state.record_event(event)
                        except Exception:
                            write_failures += 1
            elapsed = max(time.perf_counter() - t0, 1e-9)

            t1 = time.perf_counter()
            events = self.engine.state.query_events(limit=n)
            read_time = time.perf_counter() - t1
            observed_ids = {event.get("id") for event in events if isinstance(event, dict)}
            verified_reads = len(expected_ids & observed_ids)
            missing_reads = max(0, n - verified_reads)
            successful_writes = max(0, n - write_failures)

            result = {
                "test": "sensor_saturation",
                "n_requested": n,
                "n_writes_successful": successful_writes,
                "n_reads_returned": len(events),
                "n_generated_ids_verified": verified_reads,
                "n_missing_ids": missing_reads,
                "write_failures": write_failures,
                "write_time_sec": round(elapsed, 4),
                "read_time_sec": round(read_time, 4),
                "write_throughput_eps": round(successful_writes / elapsed, 1),
                "passed": n > 0 and write_failures == 0 and verified_reads == n and elapsed < 60,
            }
        except Exception as exc:
            result = {"test": "sensor_saturation", "passed": False, "error": str(exc)}
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
            "p95_ms": round(self._percentile(latencies, 0.95), 2),
            "p99_ms": round(self._percentile(latencies, 0.99), 2),
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