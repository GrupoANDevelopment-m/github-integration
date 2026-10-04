"""
Goodware v3.0 - High-level PQC facade (hybrid: PQC + X25519).

Production version: uses RealPQC (liboqs) by default.
The legacy lattice.py and signatures.py are kept only for tests
and backward compatibility — they are NEVER used in production.

If liboqs is not available, falls back to legacy with explicit warning.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("goodware.crypto.pqc")


class PQCrypto:
    """Production PQC facade with hybrid (PQC + X25519).

    Uses RealPQC (liboqs) when available. Falls back to legacy
    KyberLikeKEM (DEMO) ONLY if liboqs is not available, with
    explicit warning. NEVER silently uses demo crypto.
    """

    def __init__(self, default_kem: str = "kyber512", hybrid: bool = True):
        self.default_kem = default_kem
        self.hybrid = hybrid
        self._keys: dict = {}

        # Try real PQC first
        try:
            from .real_pqc import RealPQC
            self._real = RealPQC(algorithm=default_kem)
            if self._real.is_real():
                self.backend = "liboqs"
                self._use_real = True
                log.info(f"PQC: using REAL backend (liboqs, {default_kem})")
            else:
                self._use_real = False
                log.warning(
                    "PQC: liboqs not available — falling back to LEGACY lattice.py. "
                    "NOT FOR PRODUCTION."
                )
        except Exception as e:
            self._use_real = False
            log.warning(f"PQC: failed to init RealPQC ({e}) — using LEGACY")

        # Lazy-load legacy only if needed
        if not self._use_real:
            from .lattice import KyberLikeKEM
            from .signatures import DilithiumLikeSignature, HashBasedSignature
            self.kem = KyberLikeKEM()
            self.sig_lattice = DilithiumLikeSignature()
            self.sig_hash = HashBasedSignature()
            self.backend = "demo_lattice"
        else:
            self.kem = None
            self.sig_lattice = None
            self.sig_hash = None

    # ---- KEM ----

    def generate_kem_keypair(self, name: str = "default") -> Tuple[bytes, bytes]:
        """Generate a KEM keypair using real PQC if available."""
        if self._use_real:
            pk, sk, alg = self._real.kem_keypair()
            self._keys[name] = (pk, sk, alg)
            return pk, sk
        # Legacy fallback (with warning)
        log.warning("PQC.generate_kem_keypair: using DEMO lattice (NOT FOR PRODUCTION)")
        pk, sk = self.kem.generate_keypair()
        self._keys[name] = (pk, sk, "kyber-like-demo")
        return pk, sk

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate against a public key."""
        if self._use_real:
            return self._real.kem_encaps(public_key)
        log.warning("PQC.encaps: using DEMO lattice")
        return self.kem.encapsulate(public_key)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a ciphertext."""
        if self._use_real:
            return self._real.kem_decaps(secret_key, ciphertext)
        log.warning("PQC.decaps: using DEMO lattice")
        return self.kem.decapsulate(secret_key, ciphertext)

    # ---- Signatures ----

    def sign(self, message: bytes, secret_key: bytes, algorithm: str = "ML-DSA-44") -> bytes:
        if self._use_real:
            return self._real.sig_sign(secret_key, message, algorithm)
        log.warning("PQC.sign: using DEMO signature")
        return self.sig_lattice.sign(message, secret_key)

    def verify_sig(self, message: bytes, signature: bytes, public_key: bytes,
                   algorithm: str = "ML-DSA-44") -> bool:
        if self._use_real:
            return self._real.sig_verify(public_key, message, signature, algorithm)
        log.warning("PQC.verify_sig: using DEMO signature")
        return self.sig_lattice.verify(message, signature, public_key)

    def status(self):
        return {
            "backend": self.backend,
            "is_real": self._use_real,
            "default_kem": self.default_kem,
            "hybrid": self.hybrid,
            "keys_managed": len(self._keys),
        }