"""
Goodware v3.0 — Health checks robustos.

Devolve estado detalhado de cada componente:
- Engine
- Sensors
- Database
- LLM Harness
- Crypto
- Network
- Storage
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path

log = logging.getLogger("goodware.api.health")


def check_engine(engine) -> dict:
    try:
        status = engine.status()
        return {
            "ok": True,
            "components": len(status.get("components", [])),
            "uptime": status.get("uptime", 0),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_database(db_path: str = "/workspace/goodware-v3/data/goodware.db") -> dict:
    try:
        if not os.path.exists(db_path):
            return {"ok": False, "error": "database file not found"}
        conn = sqlite3.connect(db_path, timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM sqlite_master")
        table_count = cur.fetchone()[0]
        cur.execute("PRAGMA integrity_check")
        integrity = cur.fetchone()[0]
        conn.close()
        size_mb = os.path.getsize(db_path) / 1024 / 1024
        return {
            "ok": integrity == "ok",
            "tables": table_count,
            "integrity": integrity,
            "size_mb": round(size_mb, 2),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_crypto() -> dict:
    try:
        from goodware.crypto.real_pqc import RealPQC, OQS_AVAILABLE
        r = RealPQC()
        info = {
            "pqc_available": r.is_real(),
            "oqs_module_loaded": OQS_AVAILABLE,
        }
        if r.is_real():
            info["algorithms"] = {
                "kems": r._oqs.available_kems(),
                "sigs": r._oqs.available_sigs(),
            }
            info["version"] = r._oqs.version()
        return {"ok": True, **info}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_llm() -> dict:
    try:
        from goodware.llm.brain import get_brain
        brain = get_brain()
        if brain is None:
            return {"ok": True, "available": False, "note": "harness not started"}
        return {"ok": True, "available": brain.available}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_disk(path: str = "/workspace/goodware-v3") -> dict:
    try:
        import shutil
        total, used, free = shutil.disk_usage(path)
        free_pct = free / total * 100
        return {
            "ok": free_pct > 5,
            "total_gb": round(total / 1024**3, 2),
            "used_gb": round(used / 1024**3, 2),
            "free_gb": round(free / 1024**3, 2),
            "free_pct": round(free_pct, 2),
            "warning": free_pct < 10,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_memory() -> dict:
    try:
        import psutil
        mem = psutil.virtual_memory()
        return {
            "ok": mem.percent < 95,
            "total_gb": round(mem.total / 1024**3, 2),
            "used_pct": mem.percent,
            "available_gb": round(mem.available / 1024**3, 2),
            "warning": mem.percent > 90,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_cpu() -> dict:
    try:
        import psutil
        cpu_pct = psutil.cpu_percent(interval=1)
        load_avg = os.getloadavg()
        return {
            "ok": cpu_pct < 95,
            "cpu_pct": cpu_pct,
            "load_1m": load_avg[0],
            "load_5m": load_avg[1],
            "load_15m": load_avg[2],
            "warning": cpu_pct > 85,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_all(engine=None) -> dict:
    """Run all health checks."""
    start = time.time()
    checks = {
        "engine": check_engine(engine) if engine else {"ok": True, "skipped": "no engine"},
        "database": check_database(),
        "crypto": check_crypto(),
        "llm": check_llm(),
        "disk": check_disk(),
        "memory": check_memory(),
        "cpu": check_cpu(),
    }
    
    overall_ok = all(c.get("ok", False) for c in checks.values())
    elapsed = time.time() - start
    
    return {
        "ok": overall_ok,
        "timestamp": time.time(),
        "version": "3.0",
        "checks": checks,
        "elapsed_ms": round(elapsed * 1000, 2),
    }
