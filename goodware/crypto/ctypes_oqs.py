"""
Goodware v3.0 - Real liboqs Python bindings via ctypes.

Carrega liboqs.so directamente. Usa as funções de baixo nível (kem_kyber_512_keypair,
kem_kyber_512_encaps, etc) que estão sempre presentes na liboqs partilhada, e
reconstrói os structs OQS_KEM/OQS_SIG em memória em vez de depender dos wrappers
OQS_KEM_*_new() (que só estão disponíveis se liboqs for compilada com -DOQS_ENABLE_KEM_kyber_512).

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
    "Kyber512":       {"kind": "kem", "fn": "kyber_512",      "fn_up": "kyber_512",        "pk": 800,   "sk": 1632,  "ct": 768,  "ss": 32},
    "ML-KEM-512":     {"kind": "kem", "fn": "ml_kem_512",     "fn_up": "ML-KEM-512",       "pk": 800,   "sk": 1632,  "ct": 768,  "ss": 32},
    "Kyber768":       {"kind": "kem", "fn": "kyber_768",      "fn_up": "kyber_768",        "pk": 1184,  "sk": 2400,  "ct": 1088, "ss": 32},
    "ML-KEM-768":     {"kind": "kem", "fn": "ml_kem_768",     "fn_up": "ML-KEM-768",       "pk": 1184,  "sk": 2400,  "ct": 1088, "ss": 32},
    "Kyber1024":      {"kind": "kem", "fn": "kyber_1024",     "fn_up": "kyber_1024",       "pk": 1568,  "sk": 3168,  "ct": 1568, "ss": 32},
    "ML-KEM-1024":    {"kind": "kem", "fn": "ml_kem_1024",    "fn_up": "ML-KEM-1024",      "pk": 1568,  "sk": 3168,  "ct": 1568, "ss": 32},
    # SIGs
    "Dilithium2":     {"kind": "sig", "fn": "dilithium_2",    "fn_up": "dilithium_2",      "pk": 1312,  "sk": 2528,  "sig": 2420},
    "ML-DSA-44":      {"kind": "sig", "fn": "ml_dsa_44",      "fn_up": "ML-DSA-44",        "pk": 1312,  "sk": 2560,  "sig": 2420},
    "Dilithium3":     {"kind": "sig", "fn": "dilithium_3",    "fn_up": "dilithium_3",      "pk": 1952,  "sk": 4000,  "sig": 3293},
    "ML-DSA-65":      {"kind": "sig", "fn": "ml_dsa_65",      "fn_up": "ML-DSA-65",        "pk": 1952,  "sk": 4032,  "sig": 3309},
    "Dilithium5":     {"kind": "sig", "fn": "dilithium_5",    "fn_up": "dilithium_5",      "pk": 2592,  "sk": 4864,  "sig": 4595},
    "ML-DSA-87":      {"kind": "sig", "fn": "ml_dsa_87",      "fn_up": "ML-DSA-87",        "pk": 2592,  "sk": 4896,  "sig": 4627},
    "Falcon-512":     {"kind": "sig", "fn": "falcon_512",     "fn_up": "Falcon-512",       "pk": 897,   "sk": 1281,  "sig": 690},
    "FN-DSA-512":     {"kind": "sig", "fn": "fn_dsa_512",     "fn_up": "FN-DSA-512",       "pk": 897,   "sk": 1281,  "sig": 690},
    "SPHINCS+-SHA2-128s-simple": {"kind": "sig", "fn": "sphincs_sha2_128s_simple", "fn_up": "SPHINCS+-SHA2-128s-simple", "pk": 32, "sk": 64, "sig": 7856},
    "SLH-DSA-SHA2-128s":         {"kind": "sig", "fn": "slh_dsa_sha2_128s",        "fn_up": "SLH-DSA-SHA2-128s",        "pk": 32, "sk": 64, "sig": 7856},
}


def _find_oqs() -> Optional[str]:
    """Procura liboqs.so nos paths habituais, incluindo vendor/oqs/."""
    candidates = [
        # Vendor local (instalado)
        "/workspace/goodware-v3/vendor/oqs/lib/liboqs.so",
        "/workspace/goodware-v3/vendor/oqs/lib/liboqs.so.0",
        "/workspace/goodware-v3/vendor/oqs/lib/liboqs.so.0.16.0",
        # Vendored via install_deps.sh
        "vendor/oqs/lib/liboqs.so",
        "vendor/oqs/lib/liboqs.so.0",
        "vendor/oqs/lib/liboqs.so.0.16.0",
        # System paths
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


def _kem_fn_name(alg: str, op: str) -> Optional[str]:
    """Devolve o nome do símbolo C para KEM op ('keypair'|'encaps'|'decaps')."""
    if alg not in _ALG_META:
        return None
    fn = _ALG_META[alg]["fn"]
    return f"OQS_KEM_{fn}_{op}"


def _sig_fn_name(alg: str, op: str) -> Optional[str]:
    """Devolve o nome do símbolo C para SIG op ('keypair'|'sign'|'verify')."""
    if alg not in _ALG_META:
        return None
    fn = _ALG_META[alg]["fn"]
    return f"OQS_SIG_{fn}_{op}"


# Definição do struct OQS_KEM (campos usados)
class OQS_KEM(ctypes.Structure):
    _fields_ = []  # Não precisamos dos campos — passamos sempre NULL


# Definição do struct OQS_SIG (campos usados)
class OQS_SIG(ctypes.Structure):
    _fields_ = []


class LibOQS:
    """Binding Python para liboqs (NIST PQC) usando funções de baixo nível."""

    def __init__(self):
        self.path = _find_oqs()
        self._lib = None
        self._available_kems: List[str] = []
        self._available_sigs: List[str] = []
        self._init_error = None
        if self.path:
            try:
                self._lib = ctypes.CDLL(self.path)
                self._setup_functions()
                self._discover()
            except Exception as e:
                self._init_error = str(e)
                self._lib = None
        else:
            self._init_error = "liboqs.so not found"

    def is_available(self) -> bool:
        return self._lib is not None

    def init_error(self) -> Optional[str]:
        return self._init_error

    def _setup_functions(self) -> None:
        L = self._lib
        # OQS_init / version
        L.OQS_init.argtypes = []
        L.OQS_init.restype = None
        L.OQS_version.argtypes = []
        L.OQS_version.restype = ctypes.c_char_p
        # Descobrir (só usado se liboqs foi compilada com todos os wrappers)
        for fn in (
            "OQS_KEM_alg_count",
            "OQS_KEM_alg_identifier",
            "OQS_KEM_alg_is_enabled",
            "OQS_SIG_alg_count",
            "OQS_SIG_alg_identifier",
            "OQS_SIG_alg_is_enabled",
        ):
            try:
                f = getattr(L, fn)
                if fn.endswith("_count"):
                    f.argtypes = []
                    f.restype = ctypes.c_int
                elif fn.endswith("_identifier"):
                    f.argtypes = [ctypes.c_int]
                    f.restype = ctypes.c_char_p
                elif fn.endswith("_is_enabled"):
                    f.argtypes = [ctypes.c_char_p]
                    f.restype = ctypes.c_int
            except AttributeError:
                pass
        L.OQS_init()

    def _discover(self) -> None:
        """Descobre algoritmos disponíveis, baseado em símbolos C presentes."""
        # Para cada algoritmo conhecido, testa se os símbolos existem
        for alg, meta in _ALG_META.items():
            if meta["kind"] == "kem":
                fn = _kem_fn_name(alg, "keypair")
                if fn and self._has_symbol(fn):
                    self._available_kems.append(alg)
            else:  # sig
                fn = _sig_fn_name(alg, "keypair")
                if fn and self._has_symbol(fn):
                    self._available_sigs.append(alg)

    def _has_symbol(self, name: str) -> bool:
        try:
            getattr(self._lib, name)
            return True
        except AttributeError:
            return False

    def version(self) -> str:
        if not self.is_available():
            return "not available"
        try:
            v = self._lib.OQS_version()
            return v.decode() if v else "?"
        except Exception:
            return "unknown"

    def available_kems(self) -> List[str]:
        return list(self._available_kems)

    def available_sigs(self) -> List[str]:
        return list(self._available_sigs)

    def _pick_kem(self, alg: Optional[str]) -> str:
        if alg:
            # Tentar pelo nome canónico
            if alg in self._available_kems:
                return alg
            # Tentar variantes (Kyber <-> ML-KEM)
            for n in self._available_kems:
                if n.replace("-", "").lower() == alg.replace("-", "").lower():
                    return n
            raise RuntimeError(f"KEM {alg} not available")
        for n in ("ML-KEM-512", "Kyber512", "ML-KEM-768", "Kyber768"):
            if n in self._available_kems:
                return n
        if self._available_kems:
            return self._available_kems[0]
        raise RuntimeError("no KEMs available")

    def _pick_sig(self, alg: Optional[str]) -> str:
        if alg:
            if alg in self._available_sigs:
                return alg
            for n in self._available_sigs:
                if n.replace("-", "").lower() == alg.replace("-", "").lower():
                    return n
            raise RuntimeError(f"SIG {alg} not available")
        for n in ("ML-DSA-44", "Dilithium2", "ML-DSA-65", "Dilithium3"):
            if n in self._available_sigs:
                return n
        if self._available_sigs:
            return self._available_sigs[0]
        raise RuntimeError("no SIGs available")

    def _kem_meta(self, alg: str) -> dict:
        if alg not in _ALG_META:
            raise RuntimeError(f"unknown KEM {alg}")
        return _ALG_META[alg]

    def _sig_meta(self, alg: str) -> dict:
        if alg not in _ALG_META:
            raise RuntimeError(f"unknown SIG {alg}")
        return _ALG_META[alg]

    def _get_kem_fn(self, alg: str, op: str):
        """Devolve function pointer para OQS_KEM_<fn>_<op>, configurado com argtypes."""
        fn_name = _kem_fn_name(alg, op)
        if not fn_name:
            raise RuntimeError(f"unknown KEM alg {alg}")
        if not self._has_symbol(fn_name):
            raise RuntimeError(f"{fn_name} not present in liboqs")
        f = getattr(self._lib, fn_name)
        if op == "keypair":
            # void OQS_KEM_<alg>_keypair(uint8_t *public_key, uint8_t *secret_key)
            f.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            f.restype = ctypes.c_int  # OQS_STATUS
        elif op == "encaps":
            # void OQS_KEM_<alg>_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key)
            f.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            f.restype = ctypes.c_int
        elif op == "decaps":
            # void OQS_KEM_<alg>_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key)
            f.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            f.restype = ctypes.c_int
        return f

    def _get_sig_fn(self, alg: str, op: str):
        fn_name = _sig_fn_name(alg, op)
        if not fn_name:
            raise RuntimeError(f"unknown SIG alg {alg}")
        if not self._has_symbol(fn_name):
            raise RuntimeError(f"{fn_name} not present in liboqs")
        f = getattr(self._lib, fn_name)
        if op == "keypair":
            f.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            f.restype = ctypes.c_int
        elif op == "sign":
            # OQS_SIG_<alg>_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key)
            f.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
                          ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            f.restype = ctypes.c_int
        elif op == "verify":
            # OQS_SIG_<alg>_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key)
            f.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                          ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            f.restype = ctypes.c_int
        return f

    # ===== KEM =====
    def kem_keypair(self, alg: Optional[str] = None) -> Tuple[bytes, bytes, str]:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_kem(alg)
        meta = self._kem_meta(alg)
        keypair = self._get_kem_fn(alg, "keypair")
        pk = ctypes.create_string_buffer(meta["pk"])
        sk = ctypes.create_string_buffer(meta["sk"])
        keypair(pk, sk)
        return bytes(pk), bytes(sk), alg

    def kem_encaps(self, public_key: bytes, alg: Optional[str] = None) -> Tuple[bytes, bytes]:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_kem(alg)
        meta = self._kem_meta(alg)
        if len(public_key) != meta["pk"]:
            raise ValueError(f"public_key wrong size: {len(public_key)} != {meta['pk']}")
        encaps = self._get_kem_fn(alg, "encaps")
        ct = ctypes.create_string_buffer(meta["ct"])
        ss = ctypes.create_string_buffer(meta["ss"])
        encaps(ct, ss, public_key)
        return bytes(ct), bytes(ss)

    def kem_decaps(self, secret_key: bytes, ciphertext: bytes, alg: Optional[str] = None) -> bytes:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_kem(alg)
        meta = self._kem_meta(alg)
        if len(secret_key) != meta["sk"]:
            raise ValueError(f"secret_key wrong size: {len(secret_key)} != {meta['sk']}")
        if len(ciphertext) != meta["ct"]:
            raise ValueError(f"ciphertext wrong size: {len(ciphertext)} != {meta['ct']}")
        decaps = self._get_kem_fn(alg, "decaps")
        ss = ctypes.create_string_buffer(meta["ss"])
        decaps(ss, ciphertext, secret_key)
        return bytes(ss)

    # ===== SIG =====
    def sig_keypair(self, alg: Optional[str] = None) -> Tuple[bytes, bytes, str]:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_sig(alg)
        meta = self._sig_meta(alg)
        keypair = self._get_sig_fn(alg, "keypair")
        pk = ctypes.create_string_buffer(meta["pk"])
        sk = ctypes.create_string_buffer(meta["sk"])
        keypair(pk, sk)
        return bytes(pk), bytes(sk), alg

    def sig_sign(self, secret_key: bytes, message: bytes, alg: Optional[str] = None) -> bytes:
        """Returns just the signature bytes. Alg is auto-detected if not provided."""
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_sig(alg)
        meta = self._sig_meta(alg)
        if len(secret_key) != meta["sk"]:
            raise ValueError(f"secret_key wrong size: {len(secret_key)} != {meta['sk']}")
        sign = self._get_sig_fn(alg, "sign")
        sig = ctypes.create_string_buffer(meta["sig"])
        sig_len = ctypes.c_size_t(meta["sig"])
        sign(sig, ctypes.byref(sig_len), message, len(message), secret_key)
        return bytes(sig[: sig_len.value])

    def sig_verify(self, public_key: bytes, message: bytes, signature: bytes, alg: Optional[str] = None) -> bool:
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_sig(alg)
        meta = self._sig_meta(alg)
        if len(public_key) != meta["pk"]:
            raise ValueError(f"public_key wrong size")
        verify = self._get_sig_fn(alg, "verify")
        r = verify(message, len(message), signature, len(signature), public_key)
        return r == 0  # OQS_SUCCESS == 0

    # ===== Compatibility layer =====
    # Métodos com nomes alternativos para compatibilidade com código antigo
    def kem_keypair_legacy(self, alg=None):
        """API estilo OQS_KEM_new() — constrói struct em memória."""
        if not self.is_available():
            raise RuntimeError("liboqs not available")
        alg = self._pick_kem(alg)
        meta = self._kem_meta(alg)
        # Para compatibilidade com código que espera OQS_KEM struct
        # devolvemos um dict com os tamanhos e funções
        return {
            "method_name": alg.encode(),
            "length_public_key": meta["pk"],
            "length_secret_key": meta["sk"],
            "length_ciphertext": meta["ct"],
            "length_shared_secret": meta["ss"],
            "_keypair_fn": self._get_kem_fn(alg, "keypair"),
            "_encaps_fn": self._get_kem_fn(alg, "encaps"),
            "_decaps_fn": self._get_kem_fn(alg, "decaps"),
            "alg": alg,
        }


# Singleton
_lib_oqs_instance: Optional[LibOQS] = None


def get_liboqs() -> LibOQS:
    global _lib_oqs_instance
    if _lib_oqs_instance is None:
        _lib_oqs_instance = LibOQS()
    return _lib_oqs_instance
