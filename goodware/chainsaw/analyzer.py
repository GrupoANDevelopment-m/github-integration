"""
Goodware v3.0 - Static malware analyzer.
"""
from __future__ import annotations
import hashlib
import os


SUSPICIOUS_PATTERNS = [
    "base64 -d", "curl|sh", "wget|bash", "/dev/tcp/", "nc -e",
    "rm -rf /", "chmod 777", "xmrig", "kdevtmpfsi", "stratum",
    "no-ip.org", "duckdns", "ngrok", "msfvenom", "/etc/shadow",
    "metasploit", "metamask", "wallet.dat", "mimikatz", "reverse_shell",
    "wanna", "ryuk", "ld.so.preload",
]


class MalwareAnalyzer:
    def analyze(self, path):
        if not os.path.exists(path):
            return {"error": "not_found"}
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                data = f.read(min(size, 1024 * 1024))
        except Exception as e:
            return {"error": str(e)}
        hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        indicators = []
        for pat in SUSPICIOUS_PATTERNS:
            if pat.lower() in text.lower():
                indicators.append(pat)
        magic = data[:8]
        risk = min(1.0, len(indicators) * 0.2)
        return {
            "size": size,
            "hashes": hashes,
            "magic_hex": magic.hex(),
            "indicators": indicators,
            "risk": risk,
        }
