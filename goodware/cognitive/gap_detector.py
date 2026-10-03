"""
Goodware v3.0 — Cognitive Loop: Capability Gap Detector.

Layer 7 of the ODC/ACAMR cognitive architecture.

Detects "what prevented me from resolving this event?" and emits a
structured gap record. Combined with Lesson Extraction (layer 8),
this drives the self-improvement loop.
"""
from __future__ import annotations
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.cognitive.gap_detector")


class CapabilityGapDetector:
    """Detect capability gaps in real-time.

    A 'gap' is recorded when:
      - An event is detected but no tool/action can resolve it
      - A tool is invoked but returns 'unavailable' / 'not_implemented'
      - A policy decision cannot be made (insufficient context)
      - The LLM Brain explicitly reports a capability gap
    """

    def __init__(self, data_dir: str = "data/cognitive"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.gaps_path = os.path.join(data_dir, "gaps.jsonl")
        self.gaps: List[Dict] = []

    def record_gap(
        self,
        event_type: str,
        target: str,
        reason: str,
        attempted_actions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        gap = {
            "ts": time.time(),
            "event_type": event_type,
            "target": target,
            "reason": reason,
            "attempted_actions": attempted_actions or [],
            "context": context or {},
            "status": "open",
        }
        self.gaps.append(gap)
        try:
            with open(self.gaps_path, "a") as f:
                f.write(json.dumps(gap) + "\n")
        except Exception as e:
            log.warning("Failed to persist gap: %s", e)
        log.info("Capability gap recorded: %s on %s — %s", event_type, target, reason)
        return gap

    def list_gaps(self, status: str = "open", limit: int = 100) -> List[Dict]:
        return [g for g in self.gaps if g.get("status") == status][-limit:]

    def close_gap(self, gap_ts: float, resolution: str) -> bool:
        for g in self.gaps:
            if abs(g.get("ts", 0) - gap_ts) < 0.001:
                g["status"] = "closed"
                g["resolution"] = resolution
                g["closed_at"] = time.time()
                return True
        return False

    def status(self) -> Dict:
        return {
            "total_gaps": len(self.gaps),
            "open_gaps": len([g for g in self.gaps if g.get("status") == "open"]),
            "closed_gaps": len([g for g in self.gaps if g.get("status") == "closed"]),
        }