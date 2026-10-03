"""
Goodware v3.0 - Hardware attestation.

Production version: This module is a LEGACY demo and should not be used
in production. Use RealHardwareAttestation from real_attestation.py instead.

Kept for backwards compatibility with tests that import
HardwareAttestation. The class returns honest "unavailable" state.

REAL implementation: goodware.physical.real_attestation.RealHardwareAttestation
  - Uses tpm2-tools (when TPM chip available)
  - Falls back to swtpm (TPM software simulator)
  - Falls back to SoftTpm (TCG spec, PQC-backed quotes)
  - NEVER returns fake PCRs

This file intentionally has minimal logic — it always reports itself as
the demo/legacy class and points users to the real implementation.
"""
from __future__ import annotations
import logging
import os
import subprocess
import time
import uuid

log = logging.getLogger("goodware.physical.attestation.legacy")


class HardwareAttestation:
    """LEGACY demo class. DO NOT use in production.

    Use RealHardwareAttestation from real_attestation.py which:
      - Reads real PCRs from /dev/tpm0 via tpm2-tools
      - Falls back to swtpm socket
      - Falls back to SoftTpm (PQC-backed)
      - Generates real quotes (not fake)
    """

    def __init__(self):
        log.warning(
            "HardwareAttestation (LEGACY) instantiated. "
            "Use RealHardwareAttestation from goodware.physical.real_attestation "
            "for production."
        )

    def attest(self):
        """Returns honest 'this is legacy' state — NOT fake PCRs."""
        return {
            "ok": False,
            "legacy": True,
            "available": False,
            "mode": "LEGACY_DEMO",
            "message": "This is the legacy demo class. Use RealHardwareAttestation.",
            "recommendation": "from goodware.physical.real_attestation import RealHardwareAttestation",
            "ts": time.time(),
        }

    def get_pcrs(self):
        """Empty PCRs — explicitly says we don't have real ones."""
        return {
            "available": False,
            "mode": "LEGACY_DEMO",
            "pcrs": {},
            "message": "no real PCRs available; use RealHardwareAttestation.get_pcrs()",
        }

    def get_quote(self, nonce: str = None):
        """No real quote available."""
        return {
            "ok": False,
            "mode": "LEGACY_DEMO",
            "quote": None,
            "signature": None,
            "message": "no real quote; use RealHardwareAttestation.get_quote()",
        }

    def status(self):
        return {
            "legacy": True,
            "mode": "LEGACY_DEMO",
            "available": False,
            "recommendation": "use RealHardwareAttestation",
        }