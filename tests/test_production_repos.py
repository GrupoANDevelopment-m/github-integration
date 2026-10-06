"""
Goodware v3.0 — Tests for production-grade repos (v3.5).

Verifies:
  - Syft catalogers/formats load
  - Cosign commands discoverable
  - Capa rules load (1,057 rules)
  - Osquery tables discoverable (314 files)
"""
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, ROOT)


class TestSyftIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.supply_chain.syft_integration import SyftIntegration
        s = SyftIntegration()
        self.assertTrue(s.available, "Syft must be vendored")
        self.assertGreater(s.status()["formats"], 3)

    def test_source(self):
        from goodware.supply_chain.syft_integration import SyftIntegration
        s = SyftIntegration()
        st = s.status()
        self.assertEqual(st["source"], "https://github.com/anchore/syft")


class TestCosignIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.supply_chain.cosign_integration import CosignIntegration
        c = CosignIntegration()
        self.assertTrue(c.available, "Cosign must be vendored")

    def test_sign_subcommands(self):
        from goodware.supply_chain.cosign_integration import CosignIntegration
        c = CosignIntegration()
        self.assertGreater(len(c.list_sign_subcommands()), 0)

    def test_source(self):
        from goodware.supply_chain.cosign_integration import CosignIntegration
        c = CosignIntegration()
        st = c.status()
        self.assertEqual(st["source"], "https://github.com/sigstore/cosign")


class TestCapaIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.chainsaw.capa_integration import CapaIntegration
        c = CapaIntegration()
        self.assertTrue(c.available, "capa must be vendored")
        self.assertTrue(c.rules_available, "capa-rules must be vendored")

    def test_rules_count(self):
        from goodware.chainsaw.capa_integration import CapaIntegration
        c = CapaIntegration()
        # capa-rules has 1,057 rules
        self.assertGreater(c.status()["rules_count"], 500)

    def test_search(self):
        from goodware.chainsaw.capa_integration import CapaIntegration
        c = CapaIntegration()
        results = c.search("encrypt")
        self.assertGreater(len(results), 0)

    def test_source(self):
        from goodware.chainsaw.capa_integration import CapaIntegration
        c = CapaIntegration()
        st = c.status()
        self.assertEqual(st["source"], "https://github.com/mandiant/capa")


class TestOsqueryIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.sensors.osquery_integration import OsqueryIntegration
        o = OsqueryIntegration()
        self.assertTrue(o.available, "osquery must be vendored")

    def test_table_files(self):
        from goodware.sensors.osquery_integration import OsqueryIntegration
        o = OsqueryIntegration()
        # osquery has 314+ table implementations
        self.assertGreater(o.status()["total_table_files"], 100)

    def test_categories(self):
        from goodware.sensors.osquery_integration import OsqueryIntegration
        o = OsqueryIntegration()
        cats = o.list_table_categories()
        self.assertIn("system", cats)
        self.assertIn("networking", cats)

    def test_source(self):
        from goodware.sensors.osquery_integration import OsqueryIntegration
        o = OsqueryIntegration()
        st = o.status()
        self.assertEqual(st["source"], "https://github.com/osquery/osquery")


if __name__ == "__main__":
    unittest.main(verbosity=2)