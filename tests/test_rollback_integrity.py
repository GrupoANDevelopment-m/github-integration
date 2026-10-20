"""Security regression tests for snapshot integrity and safe rollback."""
from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from goodware.effector.rollback import SnapshotManager


class SnapshotRollbackSecurityTests(unittest.TestCase):
    def test_tampered_archive_payload_is_rejected_before_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "important.txt"
            target.write_text("original trusted content", encoding="utf-8")
            manager = SnapshotManager(str(root / "data"))
            meta = manager.snapshot_files([str(target)], compress=True)
            target.write_text("current content must survive", encoding="utf-8")

            archive = manager.base / meta["archive"]
            with tarfile.open(archive, "w:gz") as tf:
                payload = b"tampered payload"
                info = tarfile.TarInfo("files/important.txt")
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))

            # Isolate payload validation from availability of the optional PQC backend.
            with patch.object(manager, "_pqc_verify", return_value=True):
                result = manager.rollback_files(meta["id"], verify=True)

            self.assertFalse(result["ok"])
            self.assertIn("snapshot_content_hash_mismatch",
                          [item["error"] for item in result["failed_files"]])
            self.assertEqual(target.read_text(encoding="utf-8"), "current content must survive")

    def test_archive_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.txt"
            target.write_text("trusted", encoding="utf-8")
            manager = SnapshotManager(str(root / "data"))
            meta = manager.snapshot_files([str(target)], compress=True)
            outside = root / "escape.txt"

            archive = manager.base / meta["archive"]
            with tarfile.open(archive, "w:gz") as tf:
                payload = b"escaped"
                info = tarfile.TarInfo("files/../../escape.txt")
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))

            with patch.object(manager, "_pqc_verify", return_value=True):
                result = manager.rollback_files(meta["id"], verify=True)

            self.assertFalse(result["ok"])
            self.assertIn("archive_path_traversal", result["error"])
            self.assertFalse(outside.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "trusted")

    def test_api_cannot_disable_rollback_verification(self):
        from types import SimpleNamespace
        from goodware.api.server import create_app

        class Manager:
            def __init__(self):
                self.verify_arg = None

            def rollback_files(self, snapshot_id, verify=True):
                self.verify_arg = verify
                return {"ok": False, "snapshot_id": snapshot_id}

        manager = Manager()
        env = {
            "GOODWARE_API_TOKEN": "rollback-test-token",
            "GOODWARE_API_AUTH_REQUIRED": "1",
        }
        with patch.dict("os.environ", env):
            app = create_app(SimpleNamespace(_components={}), {})
            with patch("goodware.effector.rollback.get_snapshot_manager", return_value=manager):
                response = app.test_client().post(
                    "/api/snapshot/rollback",
                    json={"snapshot_id": "snap-test", "verify": False},
                    headers={"Authorization": "Bearer rollback-test-token"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertIs(manager.verify_arg, True)

    def test_sha256_fallback_is_not_misrepresented_as_signature(self):
        with tempfile.TemporaryDirectory() as td:
            manager = SnapshotManager(td)
            payload = b"metadata"
            fallback = {
                "signature_algorithm": "sha256-fallback",
                "signature": __import__("hashlib").sha256(payload).hexdigest(),
                "public_key": None,
            }
            self.assertFalse(manager._pqc_verify(payload, fallback))


if __name__ == "__main__":
    unittest.main(verbosity=2)
