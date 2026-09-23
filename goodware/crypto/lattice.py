"""
Goodware v3.0 - Lattice-based KEM (Kyber-like, demonstration-grade).

This is a TEACHING implementation following the structure of CRYSTALS-Kyber.
For production, use a vetted library (liboqs, pqcrypto, OpenSSL 3.5+ with OQS provider).
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import numpy as np


@dataclass
class LWEParams:
    n: int = 64       # ring dimension (production: 256/512/1024)
    q: int = 3329     # modulus
    k: int = 2        # module rank
    eta: int = 2      # noise bound


class KyberLikeKEM:
    """Kyber-like lattice-based key encapsulation (demo parameters).

    A is (k, k); s, e, r are (k,); b = A s + e.
    """

    def __init__(self, params: LWEParams = None):
        self.p = params or LWEParams()
        self._vec_size = self.p.k
        self._matrix_size = self.p.k * self.p.k

    def _expand(self, seed: bytes, size: int) -> np.ndarray:
        n_bytes = size * 4
        h = hashlib.shake_256(seed).digest(n_bytes)
        return (np.frombuffer(h, dtype=np.int32)[:size] % self.p.q).astype(np.int32)

    def _small(self, size: int) -> np.ndarray:
        return np.random.randint(-self.p.eta, self.p.eta + 1, size=size, dtype=np.int32)

    def generate_keypair(self):
        seed = secrets.token_bytes(32)
        A = self._expand(seed + b"|A", self._matrix_size).reshape(self.p.k, self.p.k)
        s = self._small(self.p.k)
        e = self._small(self.p.k)
        b = (A.dot(s) + e) % self.p.q
        pk = A.tobytes() + b.tobytes()
        sk = s.tobytes()
        return pk, sk, seed

    def encapsulate(self, pk: bytes):
        A = np.frombuffer(pk[: self._matrix_size * 4], dtype=np.int32).reshape(self.p.k, self.p.k)
        b = np.frombuffer(pk[self._matrix_size * 4:], dtype=np.int32)
        m = secrets.token_bytes(32)
        seed_r = hashlib.sha256(m + b"|r").digest()
        r = self._expand(seed_r, self.p.k)
        e1 = self._small(self.p.k)
        e2 = self._small()
        u = (A.T.dot(r) + e1) % self.p.q
        m_int = int.from_bytes(m, "big") % self.p.q
        v = (int(b.dot(r)) + int(e2) + m_int) % self.p.q
        shared = hashlib.sha256(m + str(v).encode()).digest()
        ct = u.tobytes() + v.tobytes()
        return ct, shared

    def decapsulate(self, sk: bytes, ct: bytes) -> bytes:
        s = np.frombuffer(sk, dtype=np.int32)
        u = np.frombuffer(ct[: self.p.k * 4], dtype=np.int32)
        v = int(np.frombuffer(ct[self.p.k * 4 : self.p.k * 4 + 4], dtype=np.int32)[0])
        m_rec = (v - int(u.dot(s))) % self.p.q
        # recover m approximately
        m_bytes = hashlib.sha256(str(m_rec).encode()).digest()
        shared = hashlib.sha256(m_bytes + str(v).encode()).digest()
        return shared
