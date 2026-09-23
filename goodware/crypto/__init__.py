"""
Goodware v3.0 - Cryptography layer (PQC + classical hybrid).
"""
from .lattice import KyberLikeKEM, LWEParams
from .signatures import DilithiumLikeSignature, HashBasedSignature
from .pqc import PQCrypto
from .vault import QuantumVault
from .agility import CryptoAgility
from .qkd_sim import QKDSimulator


class CryptoManager:
    """Coordena todas as primitivas criptográficas do Goodware."""

    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.pqc = PQCrypto(
            default_kem=config.get("crypto.default_algorithm", "kyber512"),
            hybrid=config.get("crypto.hybrid", True),
        )
        self.vault = QuantumVault(engine, self.pqc, config.get("crypto.key_dir", "keys"))
        self.agility = CryptoAgility(engine, self.pqc)
        self.qkd = QKDSimulator()

    def start(self):
        try:
            self.pqc.generate_kem_keypair("default")
        except Exception as e:
            self.engine.logger.error(f"pqc default kem: {e}")
        try:
            self.pqc.generate_sig_keypair("default")
        except Exception as e:
            self.engine.logger.error(f"pqc default sig: {e}")
        return self.status()

    def stop(self):
        pass

    def seal(self, plaintext):
        return self.vault.seal("default", plaintext)

    def open(self, blob):
        return self.vault.open("default", blob)

    def sign(self, msg):
        return self.pqc.sign("default", msg)

    def verify(self, msg, sig, key_name="default"):
        return self.pqc.verify(key_name, msg, sig)

    def qkd_session(self, bits=256):
        return self.qkd.run_session(bits)

    def status(self):
        return {
            "algorithms": {"kem": self.pqc.default_kem, "sig": "dilithium2", "hybrid": self.pqc.hybrid},
            "keys": self.pqc.list_keys(),
            "vault_entries": len(self.vault.list_entries()),
            "weak_findings": self.agility.check_weakness(),
        }
