"""
Goodware v3.0 — Lynis integration wrapper.

Lynis is the de-facto industry standard for UNIX security auditing
and CIS benchmark compliance testing. Used by:
  - CISOfy (vendor) — 16.4k stars on GitHub
  - Millions of production servers
  - PCI-DSS, HIPAA, ISO27001 compliance tests

This wrapper invokes the real Lynis binary and parses its output
for integration with Goodware's event bus and audit log.

Source: https://github.com/CISOfy/lynis
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("goodware.chainsaw.lynis")


LYNIS_REAL_DIR = "vendor/security_tools/lynis"
LYNIS_RUN_DIR = "vendor/security_tools/lynis_run"  # Must be CWD (has ./include, ./db, etc)
LYNIS_BIN_NAME = "lynis"


class LynisIntegration:
    """Real Lynis wrapper — runs the actual CISOfy/lynis binary."""

    def __init__(self):
        # Check if the run dir has proper symlinks
        self.available = self._check_available()
        self.version = self.get_version() if self.available else None

    def _check_available(self) -> bool:
        if not os.path.isdir(LYNIS_RUN_DIR):
            return False
        bin_path = os.path.join(LYNIS_RUN_DIR, LYNIS_BIN_NAME)
        return os.path.exists(bin_path) and os.access(bin_path, os.X_OK)

    def get_version(self) -> Optional[str]:
        if not self.available:
            return None
        try:
            r = subprocess.run(
                [f"./{LYNIS_BIN_NAME}", "--version"],
                cwd=LYNIS_RUN_DIR,
                capture_output=True, text=True, timeout=10,
            )
            # First non-empty line
            for line in r.stdout.split("\n"):
                line = line.strip()
                if line and "Fatal" not in line:
                    return line
            return r.stdout.strip().split("\n")[0] if r.stdout else None
        except Exception:
            return None

    def run_audit(self, quick: bool = True, timeout: int = 300) -> Dict[str, Any]:
        """Run a real Lynis audit.

        Args:
            quick: if True, only run quick checks (faster)
            timeout: max seconds to wait

        Returns:
            {
                "ok": True/False,
                "hardening_index": int,    # 0-100
                "tests_performed": int,
                "warnings": [...],
                "suggestions": [...],
                "raw_output_lines": N,
                "real": True,
            }
        """
        if not self.available:
            return {
                "ok": False,
                "error": f"lynis not found at {LYNIS_RUN_DIR}/{LYNIS_BIN_NAME}",
                "real": False,
            }
        cmd = [f"./{LYNIS_BIN_NAME}", "audit", "system", "--no-colors", "--quiet"]
        if quick:
            cmd.append("--quick")
        try:
            r = subprocess.run(
                cmd, cwd=LYNIS_RUN_DIR,
                capture_output=True, text=True, timeout=timeout,
            )
            output = r.stdout
            # Parse hardening index
            hi_match = re.search(r"Hardening index\s*=\s*(\d+)", output)
            hi = int(hi_match.group(1)) if hi_match else None
            # Count tests
            tests_match = re.search(r"Tests performed\s*:\s*(\d+)", output)
            tests = int(tests_match.group(1)) if tests_match else 0
            # Warnings + suggestions
            warnings = re.findall(r"Warning:\s*(.+)", output)
            suggestions = re.findall(r"Suggestion:\s*(.+)", output)
            return {
                "ok": True,
                "hardening_index": hi,
                "tests_performed": tests,
                "warnings": warnings[:20],
                "suggestions": suggestions[:20],
                "warning_count": len(warnings),
                "suggestion_count": len(suggestions),
                "raw_lines": output.count("\n"),
                "real": True,
                "source": "CISOfy/lynis",
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": f"lynis timed out after {timeout}s",
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
            "available": self.available,
            "binary": f"{LYNIS_RUN_DIR}/{LYNIS_BIN_NAME}",
            "version": self.version,
            "source": "https://github.com/CISOfy/lynis",
        }
