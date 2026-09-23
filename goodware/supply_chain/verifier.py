"""Goodware v3.0 - Zero-trust verifier."""
from __future__ import annotations
import time


class ZeroTrustVerifier:
    def __init__(self, sbom, signing, engine):
        self.sbom = sbom
        self.signing = signing
        self.engine = engine

    def verify_all(self):
        sbom_result = self.sbom.verify()
        signed = self.signing.list_signed()
        try:
            from goodware.core.events import EventType
            self.engine.emit(
                EventType.SYSTEM_ATTESTATION,
                {"sbom": sbom_result, "signed_count": len(signed)},
                source="supply-chain",
            )
        except Exception:
            pass
        return {
            "sbom": sbom_result,
            "signed_artifacts": signed,
            "ts": time.time(),
        }
