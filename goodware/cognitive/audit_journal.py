"""
Goodware v3.0 — Cognitive Loop: Audit Journal.

Layer 16 of the ODC/ACAMR cognitive architecture.

Structured journal of the cognitive cycle: every gap, lesson,
proposal, approval, and integration is recorded with full
context for auditability.
"""
from __future__ import annotations
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.cognitive.audit_journal")


class CognitiveAuditJournal:
    """Append-only journal of cognitive-cycle events."""

    EVENT_TYPES = {
        "gap_detected",
        "lesson_extracted",
        "skill_proposed",
        "skill_approved",
        "skill_rejected",
        "skill_integrated",
        "constitutional_violation",
        "oob_request",
        "multiparty_request",
        "self_modification",
        "rollback_triggered",
    }

    def __init__(self, data_dir: str = "data/cognitive"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.journal_path = os.path.join(data_dir, "audit_journal.jsonl")
        self.entries: List[Dict] = []

    def record(self, event_type: str, actor: str, action: str,
               target: str = "", result: str = "ok",
               details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if event_type not in self.EVENT_TYPES:
            log.warning("Unknown journal event type: %s", event_type)
        entry = {
            "ts": time.time(),
            "event_type": event_type,
            "actor": actor,
            "action": action,
            "target": target,
            "result": result,
            "details": details or {},
        }
        self.entries.append(entry)
        try:
            with open(self.journal_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            log.warning("Failed to persist journal entry: %s", e)
        return entry

    def query(self, event_type: Optional[str] = None, since_ts: float = 0,
              limit: int = 100) -> List[Dict]:
        out = []
        for e in self.entries:
            if e.get("ts", 0) < since_ts:
                continue
            if event_type and e.get("event_type") != event_type:
                continue
            out.append(e)
        return out[-limit:]

    def status(self) -> Dict:
        return {
            "total_entries": len(self.entries),
            "by_type": self._count_by("event_type"),
        }

    def _count_by(self, field: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.entries:
            v = e.get(field, "?")
            counts[v] = counts.get(v, 0) + 1
        return counts