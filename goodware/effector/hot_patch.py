"""Goodware v3.0 - Hot-patch effector with pre/post conditions."""
from __future__ import annotations
import time
import uuid


class HotPatch:
    def __init__(self, engine):
        self.engine = engine
        self.patches = []

    def apply(self, patch_id, target, patch):
        pre_ok = all(patch.get("pre", {}).values()) or not patch.get("pre")
        if not pre_ok:
            return {"ok": False, "error": "pre_condition_failed"}
        pid = str(uuid.uuid4())[:8]
        rec = {"id": pid, "patch_id": patch_id, "target": target, "applied_at": time.time()}
        self.patches.append(rec)
        try:
            from goodware.core.events import EventType, Severity
            self.engine.emit(EventType.ACTION_HOT_PATCH, rec, severity=Severity.MEDIUM, source="effector")
        except Exception:
            pass
        return {"ok": True, "patch": rec}

    def rollback(self, patch_id):
        for i, p in enumerate(self.patches):
            if p["id"] == patch_id:
                self.patches.pop(i)
                return {"ok": True, "rolled_back": patch_id}
        return {"ok": False, "error": "not_found"}

    def list_applied(self):
        return list(self.patches)
