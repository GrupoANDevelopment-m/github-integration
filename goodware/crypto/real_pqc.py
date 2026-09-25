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
    from .ctypes_oqs import get_liboqs as _get_oqs
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
            from .ctypes_oqs import get_liboqs
            self._oqs = get_liboqs()
            if self._oqs.is_available() and len(self._oqs.available_kems()) > 0:
                self.backend = "liboqs"
        except Exception:
            self._oqs = None

    def is_real(self) -> bool:
        return self.backend == "liboqs"

    def kem_keypair(self, kem_alg: Optional[str] = None) -> Tuple[bytes, bytes, str]:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.kem_keypair(kem_alg)

    def kem_encaps(self, public_key: bytes, kem_alg: Optional[str] = None) -> Tuple[bytes, bytes]:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.kem_encaps(public_key, kem_alg)

    def kem_decaps(self, secret_key: bytes, ciphertext: bytes, kem_alg: Optional[str] = None) -> bytes:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.kem_decaps(secret_key, ciphertext, kem_alg)

    def sig_keypair(self, sig_alg: Optional[str] = None) -> Tuple[bytes, bytes, str]:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        return self._oqs.sig_keypair(sig_alg)

    def sig_sign(self, secret_key: bytes, message: bytes, sig_alg: Optional[str] = None) -> bytes:
        if not self.is_real():
            raise RuntimeError("liboqs not available")
        result = self._oqs.sig_sign(secret_key, message, sig_alg)
        if isinstance(result, tuple):
            return result[0]
        return result

    def sig_verify(self, public_key: bytes, message: bytes, signature: bytes, sig_alg: Optional[str] = None) -> bool:
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
                "available_kems": [],
                "available_sigs": [],
                "note": "DEMO — liboqs.so not found. Build from source: cd /tmp && git clone https://github.com/open-quantum-safe/liboqs && cd liboqs && mkdir build && cd build && cmake -GNinja -DBUILD_SHARED_LIBS=ON .. && ninja install && ldconfig",
            }
        return {
            "backend": "liboqs",
            "is_real": True,
            "oqs_available": OQS_AVAILABLE,
            "pqcrypto_available": PQCRYPTO_AVAILABLE,
            "available_kems": self._oqs.available_kems(),
            "available_sigs": self._oqs.available_sigs(),
            "version": self._oqs.version(),
            "note": "REAL PQC via liboqs (NIST-standardised)",
        }
