"""
Goodware v3.0 - Crypto agility (inventory + migration of weak algorithms).
"""
from __future__ import annotations

import os
import re
from typing import List


class CryptoAgility:
    """Inventaria algoritmos em uso e identifica fraquezas."""

    WEAK_PATTERNS = ["des-cbc", "3des", "md5", "sha1", "rc4", "arcfour", "diffie-hellman-group1"]

    def __init__(self, engine, pqc):
        self.engine = engine
        self.pqc = pqc

    def check_weakness(self) -> List[dict]:
        findings: List[dict] = []
        # sshd_config
        sshd = "/etc/ssh/sshd_config"
        if os.path.exists(sshd):
            try:
                with open(sshd) as f:
                    for line in f:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        low = s.lower()
                        for pat in self.WEAK_PATTERNS:
                            if pat in low:
                                findings.append({"file": sshd, "line": s, "issue": pat})
                                break
            except (PermissionError, OSError):
                pass
        # python pyca/cryptography check (best-effort for certs in /etc/ssl)
        certs_dir = "/etc/ssl/certs"
        if os.path.isdir(certs_dir):
            for fn in os.listdir(certs_dir)[:5]:
                fp = os.path.join(certs_dir, fn)
                if not os.path.isfile(fp):
                    continue
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    with open(fp, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    algo = cert.signature_hash_algorithm
                    if algo and algo.name in ("sha1", "md5"):
                        findings.append({"file": fp, "issue": f"hash:{algo.name}"})
                    pub = cert.public_key()
                    if hasattr(pub, "key_size") and pub.key_size and pub.key_size < 2048:
                        findings.append({"file": fp, "issue": f"key_size:{pub.key_size}"})
                except Exception:
                    continue
        return findings

    def migrate(self, from_alg: str, to_alg: str) -> dict:
        return {
            "migrated": 0,
            "from": from_alg,
            "to": to_alg,
            "note": "demo: no live rotation; key inventory available via list_keys()",
        }
