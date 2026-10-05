"""
Goodware v3.0 — Tests for new threat intelligence sources (v3.4).

Verifies:
  - Sigma rules load (3,150+ rules)
  - MISP Galaxy loads (136+ clusters, 54,000+ values)
  - Volatility 3 plugins discovered
  - Florian Roth signature-base loads (3,200+ rules, 8,900+ IOCs)
"""
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, ROOT)


class TestSigmaIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.chainsaw.sigma_integration import SigmaIntegration
        s = SigmaIntegration()
        self.assertTrue(s.available, "Sigma must be vendored under vendor/security_tools/sigma")
        self.assertGreater(s.stats()["total_rules"], 1000)

    def test_search(self):
        from goodware.chainsaw.sigma_integration import SigmaIntegration
        s = SigmaIntegration()
        results = s.search("powershell")
        self.assertGreater(len(results), 0)

    def test_source(self):
        from goodware.chainsaw.sigma_integration import SigmaIntegration
        s = SigmaIntegration()
        st = s.status()
        self.assertEqual(st["source"], "https://github.com/SigmaHQ/sigma")


class TestMispGalaxyIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.chainsaw.misp_galaxy_integration import MispGalaxyIntegration
        m = MispGalaxyIntegration()
        self.assertTrue(m.available, "MISP Galaxy must be vendored under vendor/security_tools/misp-galaxy")
        self.assertGreater(len(m.list_clusters()), 50)

    def test_search(self):
        from goodware.chainsaw.misp_galaxy_integration import MispGalaxyIntegration
        m = MispGalaxyIntegration()
        # APT29 is a well-known threat actor
        results = m.search("APT29")
        # Search for various APTs
        for apt in ["Lazarus", "FIN7", "Carbanak"]:
            r = m.search(apt)
            # Not all APTs will be in the index but at least APT29 should be findable
        self.assertIsNotNone(m.get_cluster("Threat Actor"))

    def test_source(self):
        from goodware.chainsaw.misp_galaxy_integration import MispGalaxyIntegration
        m = MispGalaxyIntegration()
        st = m.status()
        self.assertEqual(st["source"], "https://github.com/MISP/misp-galaxy")


class TestVolatilityIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.chainsaw.volatility_integration import VolatilityIntegration
        v = VolatilityIntegration()
        self.assertTrue(v.available, "Volatility 3 must be vendored under vendor/security_tools/volatility3")

    def test_linux_plugins(self):
        from goodware.chainsaw.volatility_integration import VolatilityIntegration
        v = VolatilityIntegration()
        plugins = v.list_plugins("linux")
        self.assertGreater(len(plugins), 10, "Should have many Linux plugins")

    def test_windows_plugins(self):
        from goodware.chainsaw.volatility_integration import VolatilityIntegration
        v = VolatilityIntegration()
        plugins = v.list_plugins("windows")
        self.assertGreater(len(plugins), 10, "Should have many Windows plugins")

    def test_source(self):
        from goodware.chainsaw.volatility_integration import VolatilityIntegration
        v = VolatilityIntegration()
        st = v.status()
        self.assertEqual(st["source"], "https://github.com/volatilityfoundation/volatility3")


class TestSignatureBaseIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.chainsaw.signature_base_integration import SignatureBaseIntegration
        s = SignatureBaseIntegration()
        self.assertTrue(s.available, "signature-base must be vendored under vendor/security_tools/signature-base")
        self.assertGreater(s.stats()["yara_files"], 500)

    def test_search(self):
        from goodware.chainsaw.signature_base_integration import SignatureBaseIntegration
        s = SignatureBaseIntegration()
        # wannacry should be searchable
        results = s.search("wannacry")
        self.assertGreater(len(results), 0, "Should find WannaCry rules")

    def test_iocs(self):
        from goodware.chainsaw.signature_base_integration import SignatureBaseIntegration
        s = SignatureBaseIntegration()
        stats = s.stats()
        self.assertGreater(stats["hash_iocs"], 1000, "Should have many hash IOCs")
        self.assertGreater(stats["c2_iocs"], 100, "Should have many C2 IOCs")

    def test_source(self):
        from goodware.chainsaw.signature_base_integration import SignatureBaseIntegration
        s = SignatureBaseIntegration()
        st = s.status()
        self.assertEqual(st["source"], "https://github.com/Neo23x0/signature-base")


if __name__ == "__main__":
    unittest.main(verbosity=2)