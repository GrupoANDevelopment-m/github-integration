"""Goodware v3.0 - Physical security (real TPM/auditd)."""
from .attestation import HardwareAttestation
from .memory_protection import MemoryProtection
from .real_attestation import RealHardwareAttestation, RealAuditd


class PhysicalSecurityManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.attestation = HardwareAttestation()  # demo fallback
        self.attestation_real = RealHardwareAttestation()  # real
        self.auditd_real = RealAuditd()
        self.memory = MemoryProtection()

    def start(self):
        return self.attest_now()

    def stop(self):
        pass

    def attest_now(self):
        a = self.attestation_real.attest()  # REAL
        m = self.memory.prevent_dma()
        a["trust_level"] = "high" if a["tpm_present"] and a["secure_boot"] else ("medium" if a["tpm_present"] else "low")
        auditd = self.auditd_real.status()
        return {"attestation": a, "dma_prevention": m, "auditd": auditd}

    def add_audit_watch(self, path: str) -> dict:
        """Adiciona watch real no auditd."""
        return self.auditd_real.add_watch(path)

    def add_syscall_watch(self, syscall: str) -> dict:
        return self.auditd_real.add_syscall_watch(syscall)

    def query_audit_recent(self, key: str = "goodware") -> dict:
        return self.auditd_real.query_recent(key=key)

    def status(self):
        return self.attest_now()
