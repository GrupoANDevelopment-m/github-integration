"""
Goodware v3.0 — Cognitive Loop (ODC/ACAMR Phase 1 Foundation).

This module implements the foundation of the ODC/ACAMR cognitive
architecture as proposed in Section 5 of the audit.

Layers implemented in Phase 1 (Foundation):
  - 7  Capability Gap Detector    (gap_detector.py)
  - 8  Lesson Extraction          (lesson_extraction.py)
  - 16 Audit Journal              (audit_journal.py)

Future phases (not yet implemented):
  - 3  Goal Engine
  - 4-6 Reasoning / Hypotheses / Evidence (orchestrated through DeepSeek)
  - 9  Knowledge Synthesis
  - 10 Skill Creation
  - 11 Implementation (ex-OpenCode → DeepSeek Harness)
  - 12 Sandbox for code/skills
  - 13 Constitutional Guard  ← already implemented in goodware/security/
  - 14 Self-Refinement
  - 15 Rollback Manager     ← already implemented in goodware/effector/rollback.py
  - 17 Cognitive Memory     ← already in goodware/llm/memory.py
  - 18 Capability Index
  - 19 Recursive Improvement
"""
from .gap_detector import CapabilityGapDetector
from .lesson_extraction import LessonExtractor
from .audit_journal import CognitiveAuditJournal

__all__ = [
    "CapabilityGapDetector",
    "LessonExtractor",
    "CognitiveAuditJournal",
]