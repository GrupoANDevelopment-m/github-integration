"""
Goodware v3.0 - Cryptography layer (PQC + classical hybrid).

Production version: uses RealPQC (liboqs) by default, not the
demonstration-grade lattice.py.

The demonstration modules (lattice.py, signatures.py) are still
importable for testing/teaching but NOT used in production paths.
"""
from .lattice import KyberLikeKEM, LWEParams  # noqa: F401 — legacy/demo
from .signatures import DilithiumLikeSignature, HashBasedSignature  # noqa: F401 — legacy/demo
from .real_pqc import RealPQC, OQS_AVAILABLE  # noqa: F401 — production
from .pqc import PQCrypto  # noqa: F401 — legacy facade
from .vault import QuantumVault
from .agility import CryptoAgility
from .qkd_sim import QKDSimulator


class CryptoManager:
    """Coordena todas as primitivas criptográficas do Goodware.

    Production: uses RealPQC (liboqs) by default — real NIST-standardised PQC.
    Falls back to PQCrypto (demo lattice) ONLY if explicitly requested AND
    RealPQC is unavailable — with honest reporting.
    """

    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        # Production path: RealPQC (liboqs)
        self.real_pqc = RealPQC(
            algorithm=config.get("crypto.default_algorithm", "Kyber512")
        )
        self.pqc_is_real = self.real_pqc.is_real()
        # Legacy facade (only for backward compat with old tests)
        self.pqc = PQCrypto(
            default_kem=config.get("crypto.default_algorithm", "kyber512"),
            hybrid=config.get("crypto.hybrid", True),
        )
        self.vault = QuantumVault(engine, self.pqc, config.get("crypto.key_dir", "keys"))
        self.agility = CryptoAgility(engine, self.pqc)
        self.qkd = QKDSimulator()

    def start(self):
        try:
            if self.pqc_is_real:
                # Use REAL PQC (liboqs)
                pk, sk, alg = self.real_pqc.kem_keypair()
                self.engine.logger.info(
                    f"Crypto: REAL PQC via liboqs ({alg})"
                )
            else:
                self.engine.logger.warning(
                    "Crypto: liboqs.so not loaded — falling back to DEMO lattice "
                    "(NOT FOR PRODUCTION)"
                )
                self.pqc.generate_kem_keypair("default")
        except Exception as e:
            self.engine.logger.error(f"crypto start: {e}")

    def kem_keypair(self):
        """Generate a KEM keypair — REAL if available."""
        if self.pqc_is_real:
            return self.real_pqc.kem_keypair()
        # Fallback to demo (with warning)
        self.engine.logger.warning("Real PQC unavailable; using demo lattice")
        return self.pqc.kem.generate_keypair()

    def kem_encaps(self, public_key):
        if self.pqc_is_real:
            return self.real_pqc.kem_encaps(public_key)
        return self.pqc.kem.encapsulate(public_key)

    def kem_decaps(self, secret_key, ciphertext):
        if self.pqc_is_real:
            return self.real_pqc.kem_decaps(secret_key, ciphertext)
        return self.pqc.kem.decapsulate(secret_key, ciphertext)

    def sig_keypair(self, algorithm="ML-DSA-44"):
        if self.pqc_is_real:
            return self.real_pqc.sig_keypair(algorithm)
        return self.pqc.sig_lattice.generate_keypair()

    def sign(self, message, secret_key, algorithm="ML-DSA-44"):
        if self.pqc_is_real:
            return self.real_pqc.sig_sign(secret_key, message, algorithm)
        return self.pqc.sig_lattice.sign(message, secret_key)

    def verify(self, message, signature, public_key, algorithm="ML-DSA-44"):
        if self.pqc_is_real:
            return self.real_pqc.sig_verify(public_key, message, signature, algorithm)
        return self.pqc.sig_lattice.verify(message, signature, public_key)

    def status(self):
        return {
            "pqc_real": self.pqc_is_real,
            "pqc_backend": "liboqs" if self.pqc_is_real else "demo_lattice",
            "vault_keys": len(self.vault.list_keys()),
            "agility_algorithms": self.agility.list_algorithms(),
        }