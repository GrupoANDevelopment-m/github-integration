"""
Goodware v3.0 - State Management
Persistência de estado (regras, modelos, eventos, políticas) com SQLite.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT,
    timestamp REAL NOT NULL,
    payload TEXT,
    correlation_id TEXT,
    tags TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);

CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    signature TEXT UNIQUE,
    description TEXT,
    severity TEXT,
    first_seen REAL,
    last_seen REAL,
    count INTEGER DEFAULT 1,
    source TEXT,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_threats_sev ON threats(severity);

CREATE TABLE IF NOT EXISTS quarantined (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    sha256 TEXT,
    reason TEXT,
    severity TEXT,
    quarantined_at REAL,
    restored_at REAL
);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT,
    created_at REAL,
    enabled INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS predictions (
    id TEXT PRIMARY KEY,
    horizon_hours REAL,
    threat_type TEXT,
    confidence REAL,
    risk_score REAL,
    explanation TEXT,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS keys (
    name TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key BLOB,
    secret_key BLOB,
    metadata TEXT,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS models (
    name TEXT PRIMARY KEY,
    version TEXT,
    path TEXT,
    metrics TEXT,
    trained_at REAL,
    samples INTEGER
);

CREATE TABLE IF NOT EXISTS sbom (
    component TEXT PRIMARY KEY,
    version TEXT,
    source TEXT,
    sha256 TEXT,
    verified INTEGER DEFAULT 0,
    last_check REAL
);

CREATE TABLE IF NOT EXISTS attestations (
    component TEXT PRIMARY KEY,
    measurement TEXT,
    pcr_quote TEXT,
    verified INTEGER DEFAULT 0,
    attested_at REAL
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    rules TEXT,
    active INTEGER DEFAULT 1,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT,
    target TEXT,
    decision TEXT,
    reason TEXT,
    ts REAL
);
"""


class StateStore:
    """Camada de persistência SQLite thread-safe."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    @contextmanager
    def _connect(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

    # ---- events ----
    def record_event(self, event_dict: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?)",
                (
                    event_dict["id"],
                    event_dict["type"],
                    event_dict["severity"],
                    event_dict.get("source", ""),
                    event_dict["timestamp"],
                    json.dumps(event_dict.get("payload", {})),
                    event_dict.get("correlation_id"),
                    json.dumps(event_dict.get("tags", [])),
                ),
            )
            conn.commit()

    def query_events(
        self,
        type_: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []
        if type_:
            sql += " AND type=?"
            params.append(type_)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if since:
            sql += " AND timestamp>=?"
            params.append(since)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d["payload"] or "{}")
            except Exception:
                d["payload"] = {}
            try:
                d["tags"] = json.loads(d["tags"] or "[]")
            except Exception:
                d["tags"] = []
            result.append(d)
        return result

    # ---- threats ----
    def upsert_threat(
        self,
        signature: str,
        description: str,
        severity: str,
        source: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        import uuid
        now = time.time()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, count FROM threats WHERE signature=?", (signature,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE threats SET last_seen=?, count=count+1 WHERE id=?",
                    (now, row["id"]),
                )
                return row["id"]
            tid = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO threats VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    tid,
                    signature,
                    description,
                    severity,
                    now,
                    now,
                    1,
                    source,
                    json.dumps(metadata or {}),
                ),
            )
            conn.commit()
            return tid

    def list_threats(self, severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if severity:
                rows = conn.execute(
                    "SELECT * FROM threats WHERE severity=? ORDER BY last_seen DESC LIMIT ?",
                    (severity, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM threats ORDER BY last_seen DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    # ---- quarantine ----
    def add_quarantine(
        self, item_id: str, path: str, sha256: str, reason: str, severity: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO quarantined VALUES (?,?,?,?,?,?,?)",
                (item_id, path, sha256, reason, severity, time.time(), None),
            )
            conn.commit()

    def list_quarantined(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM quarantined WHERE restored_at IS NULL ORDER BY quarantined_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- rules ----
    def add_rule(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        action: str,
        severity: str,
        source: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO rules VALUES (?,?,?,?,?,?,?,?)",
                (rule_id, name, pattern, action, severity, source, time.time(), 1),
            )
            conn.commit()

    def list_rules(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if enabled_only:
                rows = conn.execute("SELECT * FROM rules WHERE enabled=1").fetchall()
            else:
                rows = conn.execute("SELECT * FROM rules").fetchall()
        return [dict(r) for r in rows]

    def disable_rule(self, name: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE rules SET enabled=0 WHERE name=?", (name,))
            conn.commit()

    # ---- predictions ----
    def add_prediction(
        self,
        pred_id: str,
        horizon: float,
        threat_type: str,
        confidence: float,
        risk: float,
        explanation: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO predictions VALUES (?,?,?,?,?,?,?)",
                (pred_id, horizon, threat_type, confidence, risk, explanation, time.time()),
            )
            conn.commit()

    def list_predictions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM predictions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- audit ----
    def audit(self, actor: str, action: str, target: str, decision: str, reason: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit (actor, action, target, decision, reason, ts) VALUES (?,?,?,?,?,?)",
                (actor, action, target, decision, reason, time.time()),
            )
            conn.commit()

    def list_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- generic ----
    def kv_set(self, table: str, key: str, value: Dict[str, Any]) -> None:
        # mapeia tabelas específicas
        if table == "models":
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO models VALUES (?,?,?,?,?,?)",
                    (
                        key,
                        value.get("version", "1.0"),
                        value.get("path", ""),
                        json.dumps(value.get("metrics", {})),
                        value.get("trained_at", time.time()),
                        value.get("samples", 0),
                    ),
                )
                conn.commit()
        elif table == "keys":
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO keys VALUES (?,?,?,?,?,?)",
                    (
                        key,
                        value.get("algorithm", ""),
                        value.get("public_key"),
                        value.get("secret_key"),
                        json.dumps(value.get("metadata", {})),
                        value.get("created_at", time.time()),
                    ),
                )
                conn.commit()

    def kv_get(self, table: str, key: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            if table == "models":
                row = conn.execute("SELECT * FROM models WHERE name=?", (key,)).fetchone()
            elif table == "keys":
                row = conn.execute("SELECT * FROM keys WHERE name=?", (key,)).fetchone()
            else:
                return None
        if not row:
            return None
        d = dict(row)
        if d.get("metrics"):
            try:
                d["metrics"] = json.loads(d["metrics"])
            except Exception:
                pass
        return d
