"""
Goodware v3.0 — Loki Scanner integration.

Loki is a Python-based scanner from Neo23x0 (author of yarGen and
signature-base). It scans for IOCs (file hashes, YARA, regex,
C2) using multiple signature sources:

  - YARA rules
  - Regex signatures for C2 / webshells
  - Hash blocklists
  - Filename patterns

Source: https://github.com/Neo23x0/Loki
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.chainsaw.loki")


LOKI_DIR = "vendor/security_tools/Loki"
LOKI_BIN = os.path.join(LOKI_DIR, "loki.py")


class LokiIntegration:
    """Real Loki scanner wrapper.

    Loki detects:
      - File hashes from hash blocklists
      - YARA rule matches
      - Regex signatures (C2 indicators, webshells)
      - Filename patterns (known backdoors)
    """

    def __init__(self, loki_dir: str = LOKI_DIR):
        self.loki_dir = loki_dir
        self.loki_bin = os.path.join(loki_dir, "loki.py")
        self._available = self._check_available()

    def _check_available(self) -> bool:
        if not os.path.exists(self.loki_bin):
            return False
        try:
            r = subprocess.run(
                ["python3", self.loki_bin, "--help"],
                capture_output=True, text=True, timeout=10,
            )
            # Loki returns help text or non-zero
            return "Loki" in r.stdout or "Loki" in r.stderr or r.returncode in (0, 1, 2)
        except Exception:
            return False

    @property
    def available(self) -> bool:
        return self._available

    def get_version(self) -> Optional[str]:
        try:
            r = subprocess.run(
                ["python3", self.loki_bin, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            for line in (r.stdout + r.stderr).split("\n"):
                if "Loki" in line or "version" in line.lower():
                    return line.strip()
            return None
        except Exception:
            return None

    def scan(self, path: str = "/", signature_set: Optional[str] = None,
             timeout: int = 300) -> Dict[str, Any]:
        """Run Loki scan on a path.

        Args:
            path: directory or file to scan
            signature_set: optional specific signature file
            timeout: max seconds

        Returns:
            {
                "ok": True/False,
                "alerts": [...],
                "warnings": [...],
                "files_scanned": int,
                "real": True,
            }
        """
        if not self._available:
            return {
                "ok": False,
                "error": f"loki not found at {self.loki_bin}",
                "real": False,
            }
        cmd = ["python3", self.loki_bin, "--path", path, "--noprocscan",
               "--nofilescan", "--intense"]
        if signature_set:
            cmd.extend(["--sigcheck", signature_set])
        try:
            r = subprocess.run(
                cmd, cwd=self.loki_dir,
                capture_output=True, text=True, timeout=timeout,
            )
            output = r.stdout + r.stderr
            alerts = []
            warnings = []
            # Parse "ALERT:" and "WARNING:" lines
            for line in output.split("\n"):
                if "ALERT:" in line:
                    alerts.append(line.strip())
                elif "WARNING:" in line:
                    warnings.append(line.strip())
            return {
                "ok": True,
                "alerts": alerts[:50],
                "warnings": warnings[:50],
                "alert_count": len(alerts),
                "warning_count": len(warnings),
                "files_scanned": sum(1 for _ in Path(path).rglob("*") if _.is_file()) if os.path.isdir(path) else 1,
                "real": True,
                "source": "Neo23x0/Loki",
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": f"loki scan timed out after {timeout}s",
                "real": True,
            }
        except Exception as e:
            return {
                "ok": False,
                "error": str(e),
                "real": False,
            }

    def status(self) -> Dict[str, Any]:
        return {
            "available": self._available,
            "binary": self.loki_bin,
            "version": self.get_version(),
            "source": "https://github.com/Neo23x0/Loki",
        }