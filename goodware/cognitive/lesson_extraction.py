"""
Goodware v3.0 — Cognitive Loop: Lesson Extraction.

Layer 8 of the ODC/ACAMR cognitive architecture.

Converts closed capability gaps + successful actions into structured
'lessons' that can be reused by future reasoning.
"""
from __future__ import annotations
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.cognitive.lesson_extraction")


class LessonExtractor:
    """Extract lessons from events, actions, and gaps."""

    def __init__(self, data_dir: str = "data/cognitive"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.lessons_path = os.path.join(data_dir, "lessons.jsonl")
        self.lessons: List[Dict] = []

    def extract_lesson(
        self,
        lesson_type: str,
        trigger: str,
        resolution: str,
        confidence: float = 0.5,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        lesson = {
            "id": f"lesson_{int(time.time() * 1000)}",
            "ts": time.time(),
            "lesson_type": lesson_type,
            "trigger": trigger,
            "resolution": resolution,
            "confidence": confidence,
            "tags": tags or [],
            "applied_count": 0,
            "success_count": 0,
        }
        self.lessons.append(lesson)
        try:
            with open(self.lessons_path, "a") as f:
                f.write(json.dumps(lesson) + "\n")
        except Exception as e:
            log.warning("Failed to persist lesson: %s", e)
        log.info("Lesson extracted: %s — %s", lesson_type, trigger[:50])
        return lesson

    def apply_lesson(self, lesson_id: str, success: bool) -> bool:
        for l in self.lessons:
            if l.get("id") == lesson_id:
                l["applied_count"] += 1
                if success:
                    l["success_count"] += 1
                return True
        return False

    def query(self, tags: Optional[List[str]] = None, min_confidence: float = 0.0,
              limit: int = 20) -> List[Dict]:
        out = []
        for l in self.lessons:
            if l.get("confidence", 0) < min_confidence:
                continue
            if tags and not any(t in l.get("tags", []) for t in tags):
                continue
            out.append(l)
        return out[-limit:]

    def status(self) -> Dict:
        return {
            "total_lessons": len(self.lessons),
            "by_type": self._count_by("lesson_type"),
        }

    def _count_by(self, field: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for l in self.lessons:
            v = l.get(field, "?")
            counts[v] = counts.get(v, 0) + 1
        return counts