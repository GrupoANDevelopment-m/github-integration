"""
Goodware v3.0 — Cowrie SSH Honeypot integration.

Cowrie is the most widely deployed SSH/Telnet honeypot in the world.
Used by:
  - Major CSIRTs and CERTs
  - Production deception environments
  - Threat intelligence platforms

This wrapper manages Cowrie as a subprocess and integrates its
JSON logs with Goodware's event bus.

Source: https://github.com/cowrie/cowrie
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.honeypot.cowrie")


COWRIE_DIR = "vendor/security_tools/cowrie"


class CowrieIntegration:
    """Real Cowrie SSH honeypot manager.

    Cowrie provides:
      - SSH honeypot on port 2222 (configurable)
      - Telnet honeypot on port 2223
      - JSON event logs in cowrie.log
      - SFTP/SCP support
      - File upload/download capture
      - Brute-force detection
    """

    def __init__(self, cowrie_dir: str = COWRIE_DIR):
        self.cowrie_dir = cowrie_dir
        self.process: Optional[subprocess.Popen] = None
        self._available = self._check_available()

    def _check_available(self) -> bool:
        """Check if Cowrie is installed."""
        # Cowrie v3+ uses Python package
        try:
            r = subprocess.run(
                ["python3", "-c", "import cowrie; print(cowrie.__version__)"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
        # Fallback: check if dir exists with cowrie.py
        return os.path.exists(os.path.join(self.cowrie_dir, "cowrie", "__init__.py"))

    @property
    def available(self) -> bool:
        return self._available

    def get_version(self) -> Optional[str]:
        try:
            r = subprocess.run(
                ["python3", "-c", "import cowrie; print(cowrie.__version__)"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception:
            pass
        return None

    def install(self) -> bool:
        """Install Cowrie via pip (preferred) or git."""
        try:
            r = subprocess.run(
                ["pip3", "install", "cowrie"],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                log.info("Cowrie installed via pip")
                self._available = True
                return True
        except Exception as e:
            log.warning(f"pip install cowrie failed: {e}")
        return False

    def start(self, port: int = 2222, log_path: str = "data/honeypot/cowrie.json") -> Dict[str, Any]:
        """Start the Cowrie honeypot (async, daemonized).

        Args:
            port: SSH port to listen on
            log_path: where Cowrie should write JSON event logs
        """
        if not self._available:
            return {
                "ok": False,
                "error": "cowrie not installed; call install() first or pip install cowrie",
                "real": True,
            }
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        # Write a minimal cowrie config
        cfg_dir = os.path.join(self.cowrie_dir, "etc")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_path = os.path.join(cfg_dir, "cowrie.cfg")
        cfg_content = f"""
[honeypot]
hostname = goodware-v3
log_path = {log_path}

[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = false

[output_json]
enabled = true
logfile = {log_path}
"""
        try:
            with open(cfg_path, "w") as f:
                f.write(cfg_content)
        except Exception as e:
            return {"ok": False, "error": f"config write failed: {e}"}
        # Start cowrie as subprocess
        try:
            env = os.environ.copy()
            env["COWRIE_CONFIG_DIR"] = cfg_dir
            self.process = subprocess.Popen(
                ["cowrie", "--config", cfg_path, "-n"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=self.cowrie_dir,
            )
            time.sleep(2)
            if self.process.poll() is None:
                return {
                    "ok": True,
                    "pid": self.process.pid,
                    "port": port,
                    "log_path": log_path,
                    "real": True,
                }
            else:
                return {
                    "ok": False,
                    "error": "process exited immediately",
                    "returncode": self.process.returncode,
                    "real": True,
                }
        except Exception as e:
            return {"ok": False, "error": str(e), "real": True}

    def stop(self) -> Dict[str, Any]:
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None
            return {"ok": True, "stopped": True}
        return {"ok": False, "error": "not running"}

    def parse_log(self, log_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Parse Cowrie's JSON log file into structured events."""
        log_path = log_path or "data/honeypot/cowrie.json"
        if not os.path.exists(log_path):
            return []
        events = []
        try:
            with open(log_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        continue
        except Exception as e:
            log.warning(f"Failed to parse cowrie log: {e}")
        return events

    def get_intrusions(self, log_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extract intrusion events from Cowrie log.

        Returns events where attackers attempted login, ran commands,
        or downloaded/uploaded files.
        """
        events = self.parse_log(log_path)
        intrusions = []
        for e in events:
            event_type = e.get("event", "")
            if event_type in (
                "cowrie.login.failed",
                "cowrie.login.success",
                "cowrie.command.input",
                "cowrie.session.file_download",
                "cowrie.session.file_upload",
                "cowrie.direct-tcpip.request",
            ):
                intrusions.append({
                    "type": event_type,
                    "timestamp": e.get("timestamp"),
                    "src_ip": e.get("src_ip"),
                    "username": e.get("username"),
                    "password": e.get("password"),
                    "command": e.get("input"),
                    "url": e.get("url"),
                    "filename": e.get("filename"),
                    "outfile": e.get("outfile"),
                })
        return intrusions

    def status(self) -> Dict[str, Any]:
        return {
            "available": self._available,
            "running": self.process is not None and self.process.poll() is None,
            "pid": self.process.pid if self.process else None,
            "version": self.get_version(),
            "source": "https://github.com/cowrie/cowrie",
        }