"""
Goodware v3.0 - Quantum-resistant vault (AES-256-GCM at rest).
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class QuantumVault:
    """Vault para blobs encriptados com chave AES-256-GCM."""

    def __init__(self, engine, pqc, key_dir: str = "keys"):
        self.engine = engine
        self.pqc = pqc
        self.key_dir = key_dir
        data_dir = engine.config.get("general.data_dir", "data")
        self.vault_dir = os.path.join(data_dir, "vault")
        os.makedirs(self.vault_dir, exist_ok=True)
        os.makedirs(self.key_dir, exist_ok=True)
        self._keys: dict = {}
        self._init_default_key("default")

    def _init_default_key(self, name: str):
        kp_path = os.path.join(self.key_dir, f"vault_{name}.key")
        if os.path.exists(kp_path):
            with open(kp_path, "rb") as f:
                self._keys[name] = f.read()
        else:
            self._keys[name] = secrets.token_bytes(32)
            with open(kp_path, "wb") as f:
                f.write(self._keys[name])
            try:
                os.chmod(kp_path, 0o600)
            except Exception:
                pass

    def seal(self, key_name: str, plaintext: bytes) -> bytes:
        k = self._keys.get(key_name) or self._keys.get("default")
        if not k:
            raise RuntimeError("no vault key available")
        aes = AESGCM(k)
        nonce = secrets.token_bytes(12)
        ct = aes.encrypt(nonce, plaintext, None)
        blob = nonce + ct
        try:
            bid = hashlib.sha256(blob).hexdigest()[:16]
            with open(os.path.join(self.vault_dir, f"{key_name}_{bid}.bin"), "wb") as f:
                f.write(blob)
        except Exception:
            pass
        return blob

    def open(self, key_name: str, blob: bytes) -> bytes:
        k = self._keys.get(key_name) or self._keys.get("default")
        if not k:
            raise RuntimeError("no vault key available")
        aes = AESGCM(k)
        nonce, ct = blob[:12], blob[12:]
        return aes.decrypt(nonce, ct, None)

    def list_entries(self) -> list:
        if not os.path.isdir(self.vault_dir):
            return []
        return [f for f in os.listdir(self.vault_dir) if f.endswith(".bin")]
