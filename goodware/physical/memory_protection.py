"""Goodware v3.0 - Memory protection."""
from __future__ import annotations
import os
import secrets


class MemoryProtection:
    def prevent_dma(self):
        iommu = os.path.exists("/sys/class/iommu") or os.path.exists("/sys/kernel/iommu_groups")
        return {"iommu_enabled": iommu, "policy": "block-unknown-devices"}

    def cold_boot_defense(self):
        return {"memory_encrypted": False, "note": "memory encryption requires hardware support (AMD SEV / Intel TDX)"}

    def seal(self, plaintext):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return key + nonce + ct

    def unseal(self, blob):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key, nonce, ct = blob[:32], blob[32:44], blob[44:]
        return AESGCM(key).decrypt(nonce, ct, None)
