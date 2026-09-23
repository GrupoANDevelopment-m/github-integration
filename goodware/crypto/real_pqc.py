"""
Goodware v3.0 - Real PQC via liboqs (ctypes).
Funciona com liboqs.so compilada (NIST-standardised).
"""
from __future__ import annotations

from typing import Optional, Tuple

# Variáveis públicas pedidas pelo test_real_integrations
OQS_AVAILABLE = False
PQCRYPTO_AVAILABLE = False

try:
    from .ctypes_oqs import get_oqs as _get_oqs
    _o = _get_oqs()
    OQS_AVAILABLE = _o.is_available() and len(_o.available_kems()) > 0
except Exception:
    OQS_AVAILABLE = False


def _have_liboqs() -> bool:
    return OQS_AVAILABLE


class RealPQC:
    """Backend PQC real. Usa liboqs (NIST-standardised Kyber/Dilithium/ML-KEM/ML-DSA)."""

    def __init__(self, algorithm: str = "Kyber512"):
        self.algorithm = algorithm
        self.backend = "internal"
        self._oqs = None
        try:
            from .ctypes_oqs import get_oqs
            self._oqs = get_oqs()
            if self._oqs.is_available() and len(self._oqs.available_kems()) > 0:
                self.backend = "liboqs"
        except Exception:
            self._oqs = None

    def is_real(self) -> bool:
        return self.backend == "liboqs"

    def kem_keypair(self) -> Tuple[bytes, bytes, str]:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.kem_keypair()

    def kem_encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.kem_encaps(public_key)

    def kem_decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.kem_decaps(secret_key, ciphertext)

    def sig_keypair(self, sig_alg: str = None) -> Tuple[bytes, bytes, str]:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.sig_keypair(sig_alg)

    def sig_sign(self, secret_key: bytes, message: bytes, sig_alg: str = None) -> bytes:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.sig_sign(secret_key, message, sig_alg)

    def sig_verify(self, public_key: bytes, message: bytes, signature: bytes, sig_alg: str = None) -> bool:
        if not self.is_real():
            return False
        return self._oqs.sig_verify(public_key, message, signature, sig_alg)

    def status(self) -> dict:
        if not self.is_real():
            return {
                "backend": "internal",
                "is_real": False,
                "oqs_available": OQS_AVAILABLE,
                "pqcrypto_available": PQCRYPTO_AVAILABLE,
                "note": "DEMO — liboqs.so not found. Build from source: cd /tmp && git clone https://github.com/open-quantum-safe/liboqs && cd liboqs && mkdir build && cd build && cmake -GNinja -DBUILD_SHARED_LIBS=ON .. && ninja install && ldconfig",
            }
        s = self._oqs.status()
        s["is_real"] = True
        s["backend"] = "liboqs"
        s["oqs_available"] = OQS_AVAILABLE
        s["pqcrypto_available"] = PQCRYPTO_AVAILABLE
        s["note"] = "REAL PQC via liboqs (NIST-standardised)"
        return s
