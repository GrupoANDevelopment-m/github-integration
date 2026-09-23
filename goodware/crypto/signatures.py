"""
Goodware v3.0 - Signatures (Dilithium-like lattice + hash-based).
Demonstration-grade; production should use liboqs or OpenSSL 3.5+ OQS.
"""
from __future__ import annotations

import hashlib
import secrets

import numpy as np

from .lattice import LWEParams


class DilithiumLikeSignature:
    """Lattice-based signature in the style of CRYSTALS-Dilithium (demo, simplified).

    A is (k, k); s is (k,); t = A s. Signature: e = h * s (where h = H(m) mod q).
    Verify: A e = h t.
    """

    def __init__(self):
        self.p = LWEParams()
        self._matrix_size = self.p.k * self.p.k

    def keygen(self):
        A = np.random.randint(0, self.p.q, size=(self.p.k, self.p.k), dtype=np.int32)
        s = np.random.randint(-self.p.eta, self.p.eta + 1, size=(self.p.k,), dtype=np.int32)
        t = A.dot(s) % self.p.q
        return (A.tobytes(), t.tobytes()), s.tobytes()

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        s = np.frombuffer(sk, dtype=np.int32)
        h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % self.p.q
        e = (h * s) % self.p.q
        return e.tobytes()

    def verify(self, pk: tuple, msg: bytes, sig: bytes) -> bool:
        try:
            A_bytes, t_bytes = pk
            A = np.frombuffer(A_bytes, dtype=np.int32).reshape(self.p.k, self.p.k)
            t = np.frombuffer(t_bytes, dtype=np.int32)
            e = np.frombuffer(sig, dtype=np.int32)
            h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % self.p.q
            lhs = A.dot(e) % self.p.q
            rhs = (h * t) % self.p.q
            return bool(np.array_equal(lhs, rhs))
        except Exception:
            return False


class HashBasedSignature:
    """Winternitz-like hash-based one-time signature (demo, levels truncated)."""

    def __init__(self, w: int = 8, levels: int = 8):
        self.w = w
        self.levels = levels

    def keygen(self):
        seeds = [secrets.token_bytes(32) for _ in range(self.levels)]
        public = []
        for s in seeds:
            h = s
            for _ in range(2**self.w):
                h = hashlib.sha256(h).digest()
            public.append(h)
        return b"".join(public), seeds

    def sign(self, seeds, msg: bytes) -> bytes:
        h = hashlib.sha256(msg).digest()
        n = (256 + self.w - 1) // self.w
        out_parts = []
        for i in range(min(n, self.levels)):
            chunk = int.from_bytes(h[(i * self.w) // 8 : (i * self.w) // 8 + 4], "big")
            chunk = chunk & ((1 << self.w) - 1)
            v = seeds[i]
            for _ in range(chunk):
                v = hashlib.sha256(v).digest()
            out_parts.append(v)
        return b"".join(out_parts)

    def verify(self, public: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            h = hashlib.sha256(msg).digest()
            n = (256 + self.w - 1) // self.w
            sig_parts = [sig[i * 32 : (i + 1) * 32] for i in range(min(n, self.levels))]
            pub_parts = [public[i * 32 : (i + 1) * 32] for i in range(min(n, self.levels))]
            for i, (s, p) in enumerate(zip(sig_parts, pub_parts)):
                chunk = int.from_bytes(h[(i * self.w) // 8 : (i * self.w) // 8 + 4], "big")
                chunk = chunk & ((1 << self.w) - 1)
                v = s
                for _ in range(2**self.w - chunk):
                    v = hashlib.sha256(v).digest()
                if v != p:
                    return False
            return True
        except Exception:
            return False
