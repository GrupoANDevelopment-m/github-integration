"""Goodware v3.0 - Hardware attestation."""
from __future__ import annotations
import os
import subprocess
import time
import uuid


class HardwareAttestation:
    def attest(self):
        return {
            "id": str(uuid.uuid4())[:8],
            "ts": time.time(),
            "tpm_present": os.path.exists("/sys/class/tpm/tpm0"),
            "secure_boot": self._check_secure_boot(),
            "measured_boot": self._check_measured_boot(),
            "pcrs": self._read_pcrs(),
        }

    def _check_secure_boot(self):
        try:
            out = subprocess.run(["mokutil", "--sb-state"], capture_output=True, text=True, timeout=2)
            return "SecureBoot enabled" in (out.stdout or "")
        except Exception:
            return False

    def _check_measured_boot(self):
        return os.path.exists("/sys/firmware/efi/efivars") or os.path.exists("/sys/kernel/security/tpm0")

    def _read_pcrs(self):
        # Demo PCRs (real implementation would use tpm2-tools)
        return {f"PCR{i}": f"000000000000000000000000000000000000000000000000000000000000000{i:02x}" for i in range(8)}
