"""Real local HTTP integration tests for federated authentication and updates."""
from __future__ import annotations

import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import requests

from goodware.core.config import GoodwareConfig
from goodware.federated.client import FederatedClient
from goodware.federated.server import FederatedServer


class FederatedHttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.secret = "ci-only-federated-secret-rotate-never-use-in-production"
        self.env = patch.dict(os.environ, {"GOODWARE_FEDERATED_SECRET": self.secret})
        self.env.start()
        self.config = GoodwareConfig.load()
        self.config.set("federated.host", "127.0.0.1")
        self.config.set("federated.port", 0)
        self.server = FederatedServer(SimpleNamespace(emit=lambda *a, **k: None), self.config)
        self.server.start()
        self.assertTrue(self.server.is_ready())
        self.assertIsNotNone(self.server._httpd)
        port = self.server._httpd.server_address[1]
        self.config.set("federated.server_url", f"http://127.0.0.1:{port}")
        self.client = FederatedClient(SimpleNamespace(emit=lambda *a, **k: None), self.config)

    def tearDown(self):
        try:
            self.server.stop()
            if self.server._httpd:
                self.server._httpd.server_close()
        finally:
            self.env.stop()

    def test_signed_real_http_update_is_aggregated_and_persisted_in_state(self):
        self.client.add_update([0.1, -0.2, 0.3], sample_count=4, node_id="ci-node")
        result = self.client.push_update()
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["synthetic"])
        stats = self.server.stats()
        self.assertEqual(stats["total_pushes"], 1)
        self.assertEqual(stats["unique_nodes"], 1)
        self.assertEqual(stats["history"], 1)
        self.assertIsNotNone(self.server.current_model()["model"])
        self.assertEqual(self.client._local_updates, [])

    def test_invalid_hmac_is_rejected_without_changing_model(self):
        before = self.server.stats()
        body = b'{"updates":[],"node_id":"attacker"}'
        response = requests.post(
            f"{self.config.get('federated.server_url')}/push",
            data=body,
            headers={"Content-Type": "application/json", "X-Signature": "invalid"},
            timeout=3,
        )
        self.assertEqual(response.status_code, 401)
        after = self.server.stats()
        self.assertEqual(after["total_pushes"], before["total_pushes"])
        self.assertEqual(after["current_version"], before["current_version"])

    def test_missing_secret_refuses_to_push_real_update(self):
        with patch.dict(os.environ, {"GOODWARE_FEDERATED_SECRET": ""}):
            config = GoodwareConfig.load()
            config.set("federated.node_secret", "change-me-in-production")
            config.set("federated.secret_file", "/path/that/does/not/exist")
            client = FederatedClient(SimpleNamespace(emit=lambda *a, **k: None), config)
            client.add_update([1.0, 2.0], sample_count=1)
            result = client.push_update()
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "no_secret")
        self.assertFalse(result["synthetic"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
