"""
Goodware v3.0 — Tests for real security tool integrations (vendored).

Verifies:
  - Lynis is available and version-detectable
  - Cowrie code path exists (cloned)
  - Loki code path exists
  - LinuxCheck code path exists
  - All wrappers expose `available`, `version`, `status`, `source`
"""
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, ROOT)


class TestLynisIntegration(unittest.TestCase):
    def test_available(self):
        from goodware.chainsaw.lynis_integration import LynisIntegration
        l = LynisIntegration()
        # Lynis should be available because we vendored + chmod'd it
        self.assertTrue(l.available,
                        "Lynis must be available — vendored under vendor/security_tools/lynis_run/")
        self.assertIsNotNone(l.version)

    def test_status_has_source(self):
        from goodware.chainsaw.lynis_integration import LynisIntegration
        l = LynisIntegration()
        s = l.status()
        self.assertIn("source", s)
        self.assertEqual(s["source"], "https://github.com/CISOfy/lynis")
        self.assertIn("binary", s)
        self.assertIn("version", s)


class TestCowrieIntegration(unittest.TestCase):
    def test_class_exists(self):
        from goodware.honeypot.cowrie_integration import CowrieIntegration
        # Class must exist even if not pip-installed
        self.assertIsNotNone(CowrieIntegration)

    def test_source_citation(self):
        from goodware.honeypot.cowrie_integration import CowrieIntegration
        c = CowrieIntegration()
        s = c.status()
        self.assertIn("source", s)
        self.assertEqual(s["source"], "https://github.com/cowrie/cowrie")


class TestLokiIntegration(unittest.TestCase):
    def test_class_exists(self):
        from goodware.chainsaw.loki_integration import LokiIntegration
        self.assertIsNotNone(LokiIntegration)

    def test_source_citation(self):
        from goodware.chainsaw.loki_integration import LokiIntegration
        lo = LokiIntegration()
        s = lo.status()
        self.assertIn("source", s)
        self.assertEqual(s["source"], "https://github.com/Neo23x0/Loki")


class TestLinuxCheckIntegration(unittest.TestCase):
    def test_class_exists(self):
        from goodware.chainsaw.linuxcheck_integration import LinuxCheckIntegration
        self.assertIsNotNone(LinuxCheckIntegration)

    def test_source_citation(self):
        from goodware.chainsaw.linuxcheck_integration import LinuxCheckIntegration
        lc = LinuxCheckIntegration()
        s = lc.status()
        self.assertIn("source", s)
        self.assertEqual(s["source"], "https://github.com/al0ne/LinuxCheck")


class TestVendoredRepos(unittest.TestCase):
    """Verify the actual vendored git repos exist on disk."""

    def test_lynis_repo(self):
        # The run dir has symlinks
        path = os.path.join(ROOT, "vendor/security_tools/lynis_run/lynis")
        self.assertTrue(os.path.exists(path),
                        f"Lynis binary missing at {path}")

    def test_cowrie_repo(self):
        path = os.path.join(ROOT, "vendor/security_tools/cowrie")
        self.assertTrue(os.path.isdir(path),
                        f"Cowrie directory missing at {path}")

    def test_loki_repo(self):
        path = os.path.join(ROOT, "vendor/security_tools/Loki/loki.py")
        self.assertTrue(os.path.exists(path),
                        f"Loki binary missing at {path}")

    def test_linuxcheck_repo(self):
        path = os.path.join(ROOT, "vendor/security_tools/LinuxCheck/LinuxCheck.sh")
        self.assertTrue(os.path.exists(path),
                        f"LinuxCheck missing at {path}")


if __name__ == "__main__":
    unittest.main(verbosity=2)