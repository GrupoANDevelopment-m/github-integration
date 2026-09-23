"""Goodware v3.0 - Snapshot + rollback."""
from __future__ import annotations
import os
import shutil
import time
import uuid


class Rollback:
    def __init__(self, data_dir="data"):
        self.base = os.path.join(data_dir, "snapshots")
        os.makedirs(self.base, exist_ok=True)

    def snapshot(self, label, paths):
        sid = f"snap_{int(time.time())}_{str(uuid.uuid4())[:6]}"
        sd = os.path.join(self.base, sid)
        os.makedirs(sd, exist_ok=True)
        for p in paths:
            if os.path.isfile(p):
                try:
                    shutil.copy2(p, os.path.join(sd, os.path.basename(p)))
                except Exception:
                    pass
        return {"id": sid, "label": label, "files": os.listdir(sd)}

    def rollback_to(self, snapshot_id):
        sd = os.path.join(self.base, snapshot_id)
        if not os.path.isdir(sd):
            return {"ok": False, "error": "not_found"}
        return {"ok": True, "restored_files": os.listdir(sd)}

    def list_snapshots(self):
        if not os.path.isdir(self.base):
            return []
        return os.listdir(self.base)
