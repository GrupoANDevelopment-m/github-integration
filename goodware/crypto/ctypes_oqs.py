"""
Goodware v3.0 - Real liboqs Python bindings via ctypes.

Carrega liboqs.so directamente, sem dependência de pacotes Python externos.
Suporta Kyber / ML-KEM (KEM) e Dilithium / ML-DSA (sig) — algoritmos NIST PQC.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
from typing import Dict, List, Optional, Tuple


# Tamanhos conhecidos dos algoritmos PQC (NIST final)
_ALG_META: Dict[str, dict] = {
    # KEMs
    "Kyber512":       {"kind": "kem", "pk": 800,   "sk": 1632,  "ct": 768,  "ss": 32},
    "ML-KEM-512":     {"kind": "kem", "pk": 800,   "sk": 1632,  "ct": 768,  "ss": 32},
    "Kyber768":       {"kind": "kem", "pk": 1184,  "sk": 2400,  "ct": 1088, "ss": 32},
    "ML-KEM-768":     {"kind": "kem", "pk": 1184,  "sk": 2400,  "ct": 1088, "ss": 32},
    "Kyber1024":      {"kind": "kem", "pk": 1568,  "sk": 3168,  "ct": 1568, "ss": 32},
    "ML-KEM-1024":    {"kind": "kem", "pk": 1568,  "sk": 3168,  "ct": 1568, "ss": 32},
    # SIGs
    "Dilithium2":     {"kind": "sig", "pk": 1312,  "sk": 2528,  "sig": 2420},
    "ML-DSA-44":      {"kind": "sig", "pk": 1312,  "sk": 2560,  "sig": 2420},
    "Dilithium3":     {"kind": "sig", "pk": 1952,  "sk": 4000,  "sig": 3293},
    "ML-DSA-65":      {"kind": "sig", "pk": 1952,  "sk": 4032,  "sig": 3309},
    "Dilithium5":     {"kind": "sig", "pk": 2592,  "sk": 4864,  "sig": 4595},
    "ML-DSA-87":      {"kind": "sig", "pk": 2592,  "sk": 4896,  "sig": 4627},
    "Falcon-512":     {"kind": "sig", "pk": 897,   "sk": 1281,  "sig": 690},
    "FN-DSA-512":     {"kind": "sig", "pk": 897,   "sk": 1281,  "sig": 690},
    "SPHINCS+-SHA2-128s-simple": {"kind": "sig", "pk": 32, "sk": 64,  "sig": 7856},
    "SLH-DSA-SHA2-128s":         {"kind": "sig", "pk": 32, "sk": 64,  "sig": 7856},
}


def _find_oqs() -> Optional[str]:
    """Procura liboqs.so nos paths habituais."""
    candidates = [
        "/usr/local/lib/liboqs.so",
        "/usr/local/lib/liboqs.so.0",
        "/usr/local/lib/liboqs.so.0.16.0",
        "/usr/lib/liboqs.so",
        "/usr/lib/x86_64-linux-gnu/liboqs.so",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    try:
        return ctypes.util.find_library("oqs")
    except Exception:
        return None


class LibOQS:
    """Binding Python para liboqs (NIST PQC)."""

    def __init__(self):
        self.path = _find_oqs()
        self._lib = None
        self._available_kems: List[str] = []
        self._available_sigs: List[str] = []
        if self.path:
            try:
                self._lib = ctypes.CDLL(self.path)
                self._setup_functions()
                self._discover()
            except Exception as e:
                # Não silenciar — registar para diagnóstico
                self._init_error = str(e)
                self._lib = None
        else:
            self._init_error = "liboqs.so not found"

    def is_available(self) -> bool:
        return self._lib is not None

    def _setup_functions(self) -> None:
        L = self._lib
        # OQS_init
        L.OQS_init.argtypes = []
        L.OQS_init.restype = None
        L.OQS_version.argtypes = []
        L.OQS_version.restype = ctypes.c_char_p
        # KEM API
        L.OQS_KEM_alg_count.argtypes = []
        L.OQS_KEM_alg_count.restype = ctypes.c_int
        L.OQS_KEM_alg_identifier.argtypes = [ctypes.c_int]
        L.OQS_KEM_alg_identifier.restype = ctypes.c_char_p
        L.OQS_KEM_alg_is_enabled.argtypes = [ctypes.c_char_p]
        L.OQS_KEM_alg_is_enabled.restype = ctypes.c_int
        L.OQS_KEM_new.argtypes = [ctypes.c_char_p]
        L.OQS_KEM_new.restype = ctypes.c_void_p
        L.OQS_KEM_free.argtypes = [ctypes.c_void_p]
        L.OQS_KEM_free.restype = None
        L.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        L.OQS_KEM_keypair.restype = ctypes.c_int
        L.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        L.OQS_KEM_encaps.restype = ctypes.c_int
        L.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        L.OQS_KEM_decaps.restype = ctypes.c_int
        # SIG API
        L.OQS_SIG_alg_count.argtypes = []
        L.OQS_SIG_alg_count.restype = ctypes.c_int
        L.OQS_SIG_alg_identifier.argtypes = [ctypes.c_int]
        L.OQS_SIG_alg_identifier.restype = ctypes.c_char_p
        L.OQS_SIG_alg_is_enabled.argtypes = [ctypes.c_char_p]
        L.OQS_SIG_alg_is_enabled.restype = ctypes.c_int
        L.OQS_SIG_new.argtypes = [ctypes.c_char_p]
        L.OQS_SIG_new.restype = ctypes.c_void_p
        L.OQS_SIG_free.argtypes = [ctypes.c_void_p]
        L.OQS_SIG_free.restype = None
        L.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        L.OQS_SIG_keypair.restype = ctypes.c_int
        L.OQS_SIG_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
                                    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        L.OQS_SIG_sign.restype = ctypes.c_int
        L.OQS_SIG_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                      ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        L.OQS_SIG_verify.restype = ctypes.c_int
        L.OQS_init()

    def _discover(self) -> None:
        # KEMs
        n = self._lib.OQS_KEM_alg_count()
        for i in range(n):
            name = self._lib.OQS_KEM_alg_identifier(i)
            if not name:
                continue
            n_str = name.decode()
            if self._lib.OQS_KEM_alg_is_enabled(name) == 1:
                self._available_kems.append(n_str)
        # SIGs
        n = self._lib.OQS_SIG_alg_count()
        for i in range(n):
            name = self._lib.OQS_SIG_alg_identifier(i)
            if not name:
                continue
            n_str = name.decode()
            if self._lib.OQS_SIG_alg_is_enabled(name) == 1:
                self._available_sigs.append(n_str)

    def version(self) -> str:
        if not self.is_available():
            return "not available"
        v = self._lib.OQS_version()
        return v.decode() if v else "?"

    def available_kems(self) -> List[str]:
        return list(self._available_kems)

    def available_sigs(self) -> List[str]:
        return list(self._available_sigs)

    def _pick_kem(self, alg: Optional[str]) -> str:
        if alg and alg in self._available_kems:
            return alg
        for n in ("ML-KEM-512", "Kyber512", "ML-KEM-768", "Kyber768"):
            if n in self._available_kems:
                return n
        if self._available_kems:
            return self._available_kems[0]
        raise RuntimeError("no KEMs available")

    def _pick_sig(self, alg: Optional[str]) -> str:
        if alg and alg in self._available_sigs:
            return alg
        for n in ("ML-DSA-44", "Dilithium2", "ML-DSA-65", "Dilithium3"):
            if n in self._available_sigs:
                return n
        if self._available_sigs:
            return self._available_sigs[0]
        raise RuntimeError("no SIGs available")

    def _kem_meta(self, alg: str) -> dict:
        if alg in _ALG_META:
            return _ALG_META[alg]
        raise RuntimeError(f"unknown KEM {alg} (no size info)")

    def _sig_meta(self, alg: str) -> dict:
        if alg in _ALG_META:
            return _ALG_META[alg]
        raise RuntimeError(f"unknown SIG {alg} (no size info)")

    # ===== KEM =====
    def kem_keypair(self, alg: Optional[str] = None) -> Tuple[bytes, bytes, str]:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_kem(alg)
        meta = self._kem_meta(alg)
        kem = self._lib.OQS_KEM_new(alg.encode())
        if not kem:
            raise RuntimeError(f"OQS_KEM_new failed for {alg}")
        try:
            pk = ctypes.create_string_buffer(meta["pk"])
            sk = ctypes.create_string_buffer(meta["sk"])
            r = self._lib.OQS_KEM_keypair(kem, pk, sk)
            if r != 0:
                raise RuntimeError("KEM keypair failed")
            return bytes(pk), bytes(sk), alg
        finally:
            self._lib.OQS_KEM_free(kem)

    def kem_encaps(self, public_key: bytes, alg: Optional[str] = None) -> Tuple[bytes, bytes]:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_kem(alg)
        meta = self._kem_meta(alg)
        kem = self._lib.OQS_KEM_new(alg.encode())
        if not kem:
            raise RuntimeError("OQS_KEM_new failed")
        try:
            ct = ctypes.create_string_buffer(meta["ct"])
            ss = ctypes.create_string_buffer(meta["ss"])
            r = self._lib.OQS_KEM_encaps(kem, ct, ss, public_key)
            if r != 0:
                raise RuntimeError("encaps failed")
            return bytes(ct), bytes(ss)
        finally:
            self._lib.OQS_KEM_free(kem)

    def kem_decaps(self, secret_key: bytes, ciphertext: bytes, alg: Optional[str] = None) -> bytes:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_kem(alg)
        meta = self._kem_meta(alg)
        kem = self._lib.OQS_KEM_new(alg.encode())
        if not kem:
            raise RuntimeError("OQS_KEM_new failed")
        try:
            ss = ctypes.create_string_buffer(meta["ss"])
            r = self._lib.OQS_KEM_decaps(kem, ss, ciphertext, secret_key)
            if r != 0:
                raise RuntimeError("decaps failed")
            return bytes(ss)
        finally:
            self._lib.OQS_KEM_free(kem)

    # ===== SIG =====
    def sig_keypair(self, alg: Optional[str] = None) -> Tuple[bytes, bytes, str]:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_sig(alg)
        meta = self._sig_meta(alg)
        sig = self._lib.OQS_SIG_new(alg.encode())
        if not sig:
            raise RuntimeError(f"OQS_SIG_new failed for {alg}")
        try:
            pk = ctypes.create_string_buffer(meta["pk"])
            sk = ctypes.create_string_buffer(meta["sk"])
            r = self._lib.OQS_SIG_keypair(sig, pk, sk)
            if r != 0:
                raise RuntimeError("sig keypair failed")
            return bytes(pk), bytes(sk), alg
        finally:
            self._lib.OQS_SIG_free(sig)

    def sig_sign(self, secret_key: bytes, message: bytes, alg: Optional[str] = None) -> bytes:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_sig(alg)
        meta = self._sig_meta(alg)
        sig = self._lib.OQS_SIG_new(alg.encode())
        if not sig:
            raise RuntimeError("OQS_SIG_new failed")
        try:
            sk = ctypes.create_string_buffer(secret_key, meta["sk"])
            sm = ctypes.create_string_buffer(meta["sig"])
            slen = ctypes.c_size_t(0)
            r = self._lib.OQS_SIG_sign(sig, sm, ctypes.byref(slen), message, len(message), sk)
            if r != 0:
                raise RuntimeError("sign failed")
            return bytes(sm[:slen.value])
        finally:
            self._lib.OQS_SIG_free(sig)

    def sig_verify(self, public_key: bytes, message: bytes, signature: bytes, alg: Optional[str] = None) -> bool:
        if not self.is_available():
            return False
        alg = self._pick_sig(alg)
        meta = self._sig_meta(alg)
        sig = self._lib.OQS_SIG_new(alg.encode())
        if not sig:
            return False
        try:
            pk = ctypes.create_string_buffer(public_key, meta["pk"])
            r = self._lib.OQS_SIG_verify(sig, message, len(message), signature, len(signature), pk)
            return r == 0  # OQS_SUCCESS = 0
        finally:
            self._lib.OQS_SIG_free(sig)

    def status(self) -> dict:
        return {
            "lib_path": self.path,
            "is_available": self.is_available(),
            "version": self.version() if self.is_available() else None,
            "kems_available": self._available_kems,
            "sigs_available": self._available_sigs,
            "init_error": getattr(self, "_init_error", None),
        }


# singleton
_instance: Optional[LibOQS] = None


def get_oqs() -> LibOQS:
    global _instance
    if _instance is None:
        _instance = LibOQS()
    return _instance
