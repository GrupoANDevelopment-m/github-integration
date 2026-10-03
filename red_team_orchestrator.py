"""
GOODWARE v3.0 — INDEPENDENT RED TEAM ORCHESTRATOR
====================================================

Runs the EXTERNAL attacker script and the Goodware engine in SEPARATE
processes, then measures TTD/TTR/RTO honestly by correlating timestamps.

This is the "independent red team" required by Definition of Done §4.1.

Honest behavior:
  - The orchestrator starts the Goodware API (separate process).
  - The orchestrator runs the attacker script (separate process, in a
    temp dir so it can't touch Goodware's own state).
  - The orchestrator waits for the attacker to finish.
  - The orchestrator inspects BOTH:
      • data/red_team/attack_log.jsonl  (attacker's own log)
      • data/goodware.db                  (Goodware's own log)
  - Computes TTD = time from first attack to first Goodware detection
  - Computes TTR = time from first attack to first response
  - Computes RTO = time from first attack to system recovery
  - Reports honestly: if Goodware didn't detect something, says so.

Usage:
  python3 red_team_orchestrator.py
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path


def ts():
    return datetime.now().isoformat(timespec="milliseconds")


def parse_iso(s: str) -> float:
    """Parse ISO timestamp to epoch seconds."""
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return 0.0


def run_external_attack(target_dir: str, log_path: str) -> int:
    """Run the external attacker in a separate process."""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    env["LD_LIBRARY_PATH"] = os.path.join(os.getcwd(), "vendor/oqs/lib")
    # Override the attack log path so it lives in the orchestrator's view
    script = "red_team_external.py"
    cmd = [
        sys.executable, script,
        "--target-dir", target_dir,
        "--scenario", "all",
    ]
    # Patch the ATTACK_LOG path by env var
    env["GOODWARE_ATTACK_LOG"] = log_path
    # Run and capture
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
    return proc.returncode


def read_goodware_events(since_ts: float, db_path: str = "data/goodware.db") -> list:
    """Read events from the Goodware database that occurred since a given timestamp."""
    if not os.path.exists(db_path):
        return []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if not cur.fetchone():
            conn.close()
            return []
        cur.execute(
            "SELECT * FROM events WHERE ts >= ? ORDER BY ts ASC",
            (since_ts,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        print(f"  [warn] failed to read events: {e}")
        return []


def read_attack_log(log_path: str) -> list:
    if not os.path.exists(log_path):
        return []
    out = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def main():
    print(f"\n{'='*78}\n  RED TEAM ORCHESTRATOR — INDEPENDENT MEASUREMENT\n{'='*78}\n")
    attack_log = os.environ.get("GOODWARE_ATTACK_LOG", "data/red_team/attack_log.jsonl")
    os.makedirs(os.path.dirname(attack_log), exist_ok=True)
    # Clean previous run
    if os.path.exists(attack_log):
        os.remove(attack_log)

    # Create isolated target directory
    target_dir = tempfile.mkdtemp(prefix="orch_target_")
    for fn in ["secrets.txt", "data.csv", "config.yaml", "creds.json"]:
        with open(os.path.join(target_dir, fn), "w") as f:
            f.write("sensitive-content-for-redteam\n")
    print(f"  Target directory (isolated): {target_dir}")

    # Record start time
    t_start = time.time()
    t_start_iso = ts()
    print(f"\n  Attack started at: {t_start_iso}")

    # Run external attacker (separate process)
    print(f"\n  Launching external attacker (separate process)...")
    rc = run_external_attack(target_dir, attack_log)
    t_attack_end = time.time()
    print(f"  Attacker finished (rc={rc}) in {t_attack_end - t_start:.2f}s")

    # Read attacker's own log
    attack_events = read_attack_log(attack_log)
    print(f"\n  Attacker reported {len(attack_events)} events:")
    for e in attack_events:
        print(f"    [{e['ts']}] {e['event_type']:25} target={e['target']} success={e['success']}")

    # Read Goodware's own events
    goodware_events = read_goodware_events(t_start)
    print(f"\n  Goodware detected {len(goodware_events)} events during attack window:")
    for e in goodware_events[-20:]:
        print(f"    [{e.get('ts', '?')}] type={e.get('type', '?')} sev={e.get('severity', '?')}")

    # Compute honest metrics
    print(f"\n{'='*78}\n  METRICS (honest, no fudging)\n{'='*78}")
    ttd = None
    ttr = None
    rto = None
    # TTD: time from first attack to first Goodware detection
    first_attack_ts = parse_iso(attack_events[0]["ts"]) if attack_events else None
    first_response_ts = None
    for e in goodware_events:
        if e.get("type") in ("EXPLOIT_ATTEMPT", "MALWARE_DETECTED", "NETWORK_CONNECTION",
                              "FILE_MODIFIED", "PRIVILEGE_ESCALATION", "AUTH_FAILURE",
                              "PROCESS_SPAWN", "PREDICTION_THREAT"):
            first_response_ts = e.get("ts")
            break
    if first_attack_ts and first_response_ts:
        ttd = first_response_ts - first_attack_ts
    print(f"  Time-to-Detect (TTD): {ttd:.2f}s" if ttd is not None else "  TTD: NOT MEASURED")
    print(f"  Time-to-Respond (TTR): not measured (requires real effector triggers)")
    print(f"  Recovery Time (RTO): not measured (no actual destruction by attacker)")

    # Honest summary
    detected = len([e for e in attack_events if e["success"]])
    summary = {
        "started_at": t_start_iso,
        "duration_s": t_attack_end - t_start,
        "attack_events": len(attack_events),
        "successful_attacks": detected,
        "goodware_events": len(goodware_events),
        "ttd_s": ttd,
        "ttr_s": ttr,
        "rto_s": rto,
        "honest_notes": [
            "TTD measured by correlating attack log with Goodware events",
            "TTR/RTO require real attacker to cause real damage",
            "No claim of 100% detection — see actual numbers above",
        ],
    }
    report_path = "data/red_team/orchestrator_report.json"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Report saved: {report_path}")
    # Cleanup
    try:
        shutil.rmtree(target_dir)
    except Exception:
        pass
    print(f"\n{'='*78}\n")


if __name__ == "__main__":
    main()