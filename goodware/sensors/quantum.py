"""
Goodware v3.0 - Quantum sensor (detects weak crypto in use).
"""
from __future__ import annotations

import os
import re
import time
from typing import List

from goodware.core.events import EventType
from .base import BaseSensor


_WEAK_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
_WEAK_CIPHER = ["arcfour", "arcfour128", "arcfour256", "3des-cbc", "aes128-cbc"]
_WEAK_MAC = ["hmac-md5", "hmac-md5-96", "umac-64"]


class QuantumSensor(BaseSensor):
    """Detecta uso de criptografia fraca (quebrável por computadores quânticos)."""

    def __init__(self, name: str, config) -> None:
        super().__init__(name, config)
        self.interval = 60
        self.sshd_config = "/etc/ssh/sshd_config"
        self.last_alert_ts: float = 0

    def _scan(self) -> None:
        findings: List[dict] = []
        if os.path.exists(self.sshd_config):
            try:
                with open(self.sshd_config) as f:
                    for line in f:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        low = s.lower()
                        for kw in _WEAK_KEX + _WEAK_CIPHER + _WEAK_MAC:
                            if kw in low:
                                findings.append({"file": self.sshd_config, "line": s, "weak": kw})
                                break
            except (PermissionError, OSError):
                pass
        # check certs (best-effort)
        cert_dirs = ["/etc/ssl/certs"]
        for cd in cert_dirs:
            if not os.path.isdir(cd):
                continue
            for fn in os.listdir(cd)[:20]:
                fp = os.path.join(cd, fn)
                if not os.path.isfile(fp):
                    continue
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    with open(fp, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    if cert.signature_hash_algorithm and cert.signature_hash_algorithm.name in ("sha1", "md5"):
                        findings.append({"file": fp, "weak": f"sig_hash:{cert.signature_hash_algorithm.name}"})
                    pub = cert.public_key()
                    if hasattr(pub, "key_size") and pub.key_size and pub.key_size < 2048:
                        findings.append({"file": fp, "weak": f"key_size:{pub.key_size}"})
                except Exception:
                    continue
        if findings and time.time() - self.last_alert_ts > 60:
            self.last_alert_ts = time.time()
            self.emit(
                EventType.SENSOR_QUANTUM_SUSPECT,
                {"findings": findings[:10]},
                severity="medium",
                tags=["quantum", "weak_crypto"],
            )

    def start(self) -> None:
        super().start()
        self.safe_run_forever(self.interval, self._scan, name="sensor-quantum")

    def stop(self) -> None:
        super().stop()
