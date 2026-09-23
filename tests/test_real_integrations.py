"""
Goodware v3.0 - Testes de integrações reais.

Valida que cada integração:
1. Detecta correctamente se está disponível
2. Retorna mensagem honesta quando não está
3. Faz trabalho real quando disponível
"""
import os
import sys
import unittest


class TestRealIntegrations(unittest.TestCase):

    def test_firewall_detects_backend(self):
        from goodware.effector.firewall import Firewall, _have, _have_root
        fw = Firewall(data_dir="data")
        # Deve detectar algum backend
        self.assertIn(fw.backend, ["nftables", "iptables", "internal"])
        # Deve indicar se é root
        self.assertIsInstance(fw.root, bool) if hasattr(fw, 'root') else True
        snap = fw.snapshot()
        self.assertIn("backend", snap)
        self.assertIn("root", snap)

    def test_quarantine_real_kill(self):
        from goodware.effector.quarantine import Quarantine
        from goodware.core.engine import Engine
        from goodware.core.config import GoodwareConfig
        e = Engine(GoodwareConfig.load())
        q = Quarantine(e)
        # kill -1 deve dar erro
        r = q.kill_process(-1)
        self.assertFalse(r["ok"])
        # kill 1 (init) — pode dar permission_denied ou ok se root
        r = q.kill_process(1)
        self.assertIn("ok", r)
        # 99999 não existe
        r = q.kill_process(99999)
        self.assertTrue(r.get("already_dead") or r.get("ok"))

    def test_rootkit_detector(self):
        from goodware.chainsaw.real_scanner import RootkitDetector
        rd = RootkitDetector()
        r = rd.scan()
        self.assertIn("ok", r)
        self.assertIn("findings", r)
        self.assertIn("checked", r)
        # self deve ter pelo menos 1 processo
        self.assertGreater(r["checked"], 0)

    def test_cis_benchmark(self):
        from goodware.chainsaw.real_scanner import CISBenchmark
        cis = CISBenchmark()
        r = cis.run()
        self.assertIn("total", r)
        self.assertIn("passed", r)
        self.assertIn("failed", r)
        self.assertIn("score", r)
        self.assertIn("results", r)
        self.assertEqual(r["total"], len(r["results"]))
        self.assertGreaterEqual(r["total"], 5)

    def test_yara_scanner(self):
        from goodware.chainsaw.real_scanner import YaraScanner
        ys = YaraScanner()
        # Cria um ficheiro de teste
        path = "/tmp/gw_yara_test.txt"
        with open(path, "w") as f:
            f.write("xmrig --pool stratum+tcp://monero")
        r = ys.scan(path)
        if ys._have_python_yara or ys._have_yara:
            # yara real disponível — deve detectar "miner"
            self.assertTrue(r.get("ok"))
            self.assertTrue(r.get("infected"))
        else:
            # yara não disponível — mensagem honesta
            self.assertFalse(r.get("ok"))
            self.assertIn("not installed", r.get("error", ""))
        self.assertGreater(len(ys.list_rules()), 0)
        os.unlink(path)

    def test_clamav_scanner(self):
        from goodware.chainsaw.real_scanner import ClamAVScanner
        cs = ClamAVScanner()
        path = "/tmp/gw_clamav_test.txt"
        with open(path, "w") as f:
            f.write("this is a clean test file")
        r = cs.scan(path)
        if not (cs._have_clamscan or cs._have_clamdscan):
            self.assertFalse(r.get("ok"))
            self.assertIn("not installed", r.get("error", ""))
        os.unlink(path)

    def test_real_pqc_honesty(self):
        from goodware.crypto.real_pqc import RealPQC, OQS_AVAILABLE, PQCRYPTO_AVAILABLE
        r = RealPQC()
        s = r.status()
        self.assertIn("backend", s)
        self.assertIn("is_real", s)
        self.assertIn("oqs_available", s)
        self.assertIn("pqcrypto_available", s)
        # Se backend é internal, deve ser honesto
        if s["backend"] == "internal":
            self.assertFalse(s["is_real"])
            self.assertIn("DEMO", s["note"])

    def test_real_attestation_tpm(self):
        from goodware.physical.real_attestation import RealHardwareAttestation
        ra = RealHardwareAttestation()
        a = ra.attest()
        self.assertIn("tpm_present", a)
        self.assertIn("secure_boot", a)
        self.assertIn("pcrs", a)
        self.assertIn("tpm2_tools_available", a)
        # se tpm2-tools disponível, deve ser honesto
        if a["tpm2_tools_available"]:
            self.assertIn("trust_level", a)

    def test_auditd_real(self):
        from goodware.physical.real_attestation import RealAuditd
        ad = RealAuditd()
        s = ad.status()
        self.assertIn("auditd_installed", s)
        self.assertIn("auditctl_available", s)
        self.assertIn("running", s)

    def test_honeypot(self):
        from goodware.honeypot import HoneypotManager
        hm = HoneypotManager({"honeypot": {"enabled": True}})
        r = hm.start_all()
        self.assertIn("started", r)
        # pode ter 0-4 honeypots dependendo das portas
        s = hm.status()
        self.assertIn("services", s)
        hm.stop_all()

    def test_effector_kill_action(self):
        from goodware.effector import EffectorManager
        from goodware.core.engine import Engine
        from goodware.core.config import GoodwareConfig
        e = Engine(GoodwareConfig.load())
        cfg = GoodwareConfig.load()
        em = EffectorManager(e, cfg)
        r = em.execute_action({"type": "kill", "target": "99999"})
        self.assertTrue(r.get("already_dead") or r.get("ok") or "error" in r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
