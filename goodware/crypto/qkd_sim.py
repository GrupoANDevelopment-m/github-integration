"""
Goodware v3.0 - QKD simulator (BB84-style, classical channel).
"""
from __future__ import annotations

import hashlib
import secrets

import numpy as np


class QKDSimulator:
    """Simula o protocolo BB84 — a chave final é real (derivada)."""

    def run_session(self, bits: int = 256) -> bytes:
        rng = np.random.default_rng(int.from_bytes(secrets.token_bytes(8), "big"))
        alice_bits = rng.integers(0, 2, bits)
        alice_bases = rng.integers(0, 2, bits)
        bob_bases = rng.integers(0, 2, bits)
        sifted = alice_bits[alice_bases == bob_bases]
        n = len(sifted)
        if n < 16:
            return hashlib.sha256(secrets.token_bytes(32)).digest()
        sample = max(1, n // 10)
        sifted = sifted[:-sample]
        if len(sifted) < 8:
            return hashlib.sha256(secrets.token_bytes(32)).digest()
        raw_bytes = bytes(
            int("".join(map(str, sifted[i : i + 8])), 2) for i in range(0, len(sifted) - 7, 8)
        )
        return hashlib.sha256(raw_bytes).digest()
