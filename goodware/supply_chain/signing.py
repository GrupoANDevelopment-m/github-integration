"""Goodware v3.0 - Code signing using PQC."""
from __future__ import annotations
import hashlib
import hmac
import os


class CodeSigning:
    def __init__(self, engine):
        self.engine = engine
        self.signatures_dir = "signatures"
        os.makedirs(self.signatures_dir, exist_ok=True)
        self._pq = None

    def _get_pq(self):
        if self._pq is None:
            try:
                from goodware.crypto.pqc import PQCrypto
                self._pq = PQCrypto()
                self._pq.generate_sig_keypair("supply")
            except Exception:
                self._pq = False
        return self._pq if self._pq is not False else None

    def sign(self, artifact_path):
        if not os.path.exists(artifact_path):
            return {"ok": False, "error": "not_found"}
        try:
            with open(artifact_path, "rb") as f:
                data = f.read()
            digest = hashlib.sha256(data).hexdigest()
            pq = self._get_pq()
            if pq:
                sig = pq.sign("supply", digest.encode())
            else:
                sig = hmac.new(b"goodware-supply-chain", digest.encode(), hashlib.sha256).digest()
        except Exception as e:
            return {"ok": False, "error": str(e)}
        sig_path = os.path.join(self.signatures_dir, os.path.basename(artifact_path) + ".sig")
        try:
            with open(sig_path, "wb") as f:
                f.write(sig)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "digest": digest, "sig_path": sig_path}

    def verify(self, artifact_path, sig_path=None):
        if not os.path.exists(artifact_path):
            return False
        sig_path = sig_path or os.path.join(self.signatures_dir, os.path.basename(artifact_path) + ".sig")
        if not os.path.exists(sig_path):
            return False
        try:
            with open(artifact_path, "rb") as f:
                data = f.read()
            digest = hashlib.sha256(data).hexdigest().encode()
            with open(sig_path, "rb") as f:
                sig = f.read()
            pq = self._get_pq()
            if pq:
                return pq.verify("supply", digest, sig)
            expected = hmac.new(b"goodware-supply-chain", digest, hashlib.sha256).digest()
            return hmac.compare_digest(expected, sig)
        except Exception:
            return False

    def list_signed(self):
        if not os.path.isdir(self.signatures_dir):
            return []
        return os.listdir(self.signatures_dir)
