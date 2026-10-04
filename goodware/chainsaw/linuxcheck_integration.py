"""
Goodware v3.0 — LinuxCheck integration wrapper.

LinuxCheck is a 2.1k-star Linux incident-response / forensics tool
covering 13 categories of checks:
  - Basic config
  - Network traffic
  - Cron / scheduled tasks
  - Environment variables
  - User info
  - Services
  - Bash history
  - Malicious files
  - Kernel rootkits
  - SSH backdoors
  - Webshells
  - Mining processes
  - Supply chain

Source: https://github.com/al0ne/LinuxCheck
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.chainsaw.linuxcheck")


LINUXCHECK_DIR = "vendor/security_tools/LinuxCheck"
LINUXCHECK_SCRIPT = os.path.join(LINUXCHECK_DIR, "LinuxCheck.sh")


class LinuxCheckIntegration:
    """Real LinuxCheck incident-response wrapper."""

    def __init__(self, linuxcheck_dir: str = LINUXCHECK_DIR):
        self.dir = linuxcheck_dir
        self.script = linuxcheck_dir + "/LinuxCheck.sh"
        self._available = self._check_available()

    def _check_available(self) -> bool:
        if not os.path.exists(self.script):
            return False
        return os.access(self.script, os.X_OK)

    @property
    def available(self) -> bool:
        return self._available

    def run(self, mode: str = "full", timeout: int = 300) -> Dict[str, Any]:
        """Run LinuxCheck.

        Args:
            mode: "full" (all checks) or "quick" (subset)
            timeout: max seconds
        """
        if not self._available:
            return {
                "ok": False,
                "error": f"LinuxCheck not found at {self.script}",
                "real": False,
            }
        try:
            r = subprocess.run(
                ["bash", self.script],
                cwd=self.dir,
                capture_output=True, text=True, timeout=timeout,
            )
            output = r.stdout + r.stderr
            # Parse findings
            findings = []
            for line in output.split("\n"):
                line = line.strip()
                if not line:
                    continue
                # High-risk keywords
                if any(kw in line.lower() for kw in [
                    "warning", "alert", "suspicious", "malicious",
                    "rootkit", "backdoor", "webshell", "挖矿", "mining"
                ]):
                    findings.append(line)
            return {
                "ok": True,
                "findings": findings[:100],
                "findings_count": len(findings),
                "raw_lines": output.count("\n"),
                "real": True,
                "source": "al0ne/LinuxCheck",
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": f"linuxcheck timed out after {timeout}s",
                "real": True,
            }
        except Exception as e:
            return {"ok": False, "error": str(e), "real": False}

    def status(self) -> Dict[str, Any]:
        return {
            "available": self._available,
            "binary": self.script,
            "source": "https://github.com/al0ne/LinuxCheck",
        }