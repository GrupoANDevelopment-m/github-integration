"""
Goodware v3.0 - High-level PQC facade with hybrid (Kyber + X25519).
"""
from __future__ import annotations

import hashlib
import os
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .lattice import KyberLikeKEM
from .signatures import DilithiumLikeSignature, HashBasedSignature


class PQCrypto:
    """Facade PQC com encapsulamento híbrido (PQC + X25519)."""

    def __init__(self, default_kem: str = "kyber512", hybrid: bool = True):
        self.default_kem = default_kem
        self.hybrid = hybrid
        self.kem = KyberLikeKEM()
        self.sig_lattice = DilithiumLikeSignature()
        self.sig_hash = HashBasedSignature()
        self._keys: dict = {}

    # ---- KEM ----
    def generate_kem_keypair(self, name: str) -> bytes:
        pk, sk, seed = self.kem.generate_keypair()
        self._keys[name] = {"type": "kem", "pk": pk, "sk": sk, "seed": seed}
        return pk

    def kem_encapsulate(self, peer_pk: bytes) -> Tuple[bytes, bytes]:
        ct, ss_pqc = self.kem.encapsulate(peer_pk)
        if self.hybrid:
            eph = X25519PrivateKey.generate()
            shared_x = eph.exchange(X25519PrivateKey.generate().public_key())
            ss = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"goodware-hybrid-v3",
            ).derive(ss_pqc + shared_x)
            return ct, ss
        return ct, ss_pqc

    def kem_decapsulate(self, name: str, ct: bytes) -> bytes:
        rec = self._keys.get(name)
        if not rec or rec["type"] != "kem":
            raise ValueError(f"KEM key '{name}' not found")
        ss_pqc = self.kem.decapsulate(rec["sk"], ct)
        if self.hybrid:
            shared_x = X25519PrivateKey.generate().exchange(
                X25519PrivateKey.generate().public_key()
            )
            ss = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"goodware-hybrid-v3",
            ).derive(ss_pqc + shared_x)
            return ss
        return ss_pqc

    # ---- signatures ----
    def generate_sig_keypair(self, name: str) -> bytes:
        pk, sk = self.sig_lattice.keygen()
        self._keys[name] = {"type": "sig_lattice", "pk": pk, "sk": sk}
        return pk[0] + pk[1]  # concatenated for convenience

    def sign(self, name: str, msg: bytes) -> bytes:
        rec = self._keys.get(name)
        if not rec:
            raise ValueError(f"key '{name}' not found")
        if rec["type"] == "sig_lattice":
            return self.sig_lattice.sign(rec["sk"], msg)
        if rec["type"] == "sig_hash":
            return self.sig_hash.sign(rec["sk"], msg)
        raise ValueError("unknown key type")

    def verify(self, name: str, msg: bytes, sig: bytes) -> bool:
        rec = self._keys.get(name)
        if not rec or rec["type"] != "sig_lattice":
            return False
        return self.sig_lattice.verify(rec["pk"], msg, sig)

    def list_keys(self):
        return [{"name": n, "type": v["type"]} for n, v in self._keys.items()]
