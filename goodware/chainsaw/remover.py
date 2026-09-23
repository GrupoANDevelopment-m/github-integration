"""
Goodware v3.0 - Quarantine + malicious code removal.
"""
from __future__ import annotations
import hashlib
import os
import shutil
import uuid


class MaliciousCodeRemover:
    def __init__(self, engine):
        self.engine = engine
        self.qdir = os.path.abspath(os.path.join(engine.config.get("general.data_dir", "data"), "..", "quarantine"))
        os.makedirs(self.qdir, exist_ok=True)

    def quarantine(self, path, reason):
        if not os.path.exists(path):
            return {"ok": False, "error": "not_found"}
        try:
            with open(path, "rb") as f:
                data = f.read()
            sha = hashlib.sha256(data).hexdigest()
        except Exception as e:
            return {"ok": False, "error": str(e)}
        qid = str(uuid.uuid4())[:8]
        name = os.path.basename(path)
        target = os.path.join(self.qdir, f"{sha[:16]}__{name}")
        try:
            shutil.copy2(path, target)
            try:
                os.chmod(target, 0o000)
            except Exception:
                pass
        except Exception as e:
            return {"ok": False, "error": str(e)}
        try:
            self.engine.state.add_quarantine(qid, path, sha, reason, "high")
        except Exception:
            pass
        try:
            from goodware.core.events import EventType, Severity
            self.engine.emit(EventType.ACTION_QUARANTINE, {"id": qid, "path": path, "reason": reason}, severity=Severity.HIGH, source="chainsaw")
        except Exception:
            pass
        return {"ok": True, "id": qid, "quarantine_path": target, "sha256": sha}

    def remove(self, path, indicators):
        if not os.path.exists(path):
            return {"ok": False, "error": "not_found"}
        if not path.endswith((".sh", ".py", ".txt", ".bash", ".zsh")):
            return {"ok": True, "patch_plan": True, "indicators": indicators}
        try:
            with open(path) as f:
                lines = f.readlines()
        except Exception as e:
            return {"ok": False, "error": str(e)}
        kept = []
        removed = 0
        for line in lines:
            low = line.lower()
            if any(ind.lower() in low for ind in indicators):
                removed += 1
                continue
            kept.append(line)
        clean_path = path + ".cleaned"
        try:
            with open(clean_path, "w") as f:
                f.writelines(kept)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "lines_removed": removed, "clean_path": clean_path}
