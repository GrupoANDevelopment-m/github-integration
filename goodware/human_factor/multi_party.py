"""
Goodware v3.0 - Multi-party authorization for high-stakes actions.
"""
from __future__ import annotations
import threading
import time
import uuid


class MultiPartyAuthorization:
    def __init__(self):
        self._lock = threading.Lock()
        self._requests = {}

    def request(self, action, required_approvals=2, total_approvers=3, timeout_sec=300):
        rid = str(uuid.uuid4())[:8]
        with self._lock:
            self._requests[rid] = {
                "id": rid,
                "action": action,
                "required": required_approvals,
                "total": total_approvers,
                "approvals": [],
                "rejections": [],
                "created_at": time.time(),
                "timeout_sec": timeout_sec,
                "status": "pending",
            }
        return rid

    def approve(self, request_id, admin_id):
        with self._lock:
            req = self._requests.get(request_id)
            if not req or req["status"] != "pending":
                return {"ok": False, "error": "not pending"}
            if any(a["admin"] == admin_id for a in req["approvals"]):
                return {"ok": False, "error": "duplicate"}
            req["approvals"].append({"admin": admin_id, "ts": time.time()})
            if len(req["approvals"]) >= req["required"]:
                req["status"] = "approved"
            return {"ok": True, "status": req["status"], "approvals": len(req["approvals"]), "required": req["required"]}

    def reject(self, request_id, admin_id):
        with self._lock:
            req = self._requests.get(request_id)
            if not req or req["status"] != "pending":
                return {"ok": False, "error": "not pending"}
            req["rejections"].append({"admin": admin_id, "ts": time.time()})
            req["status"] = "rejected"
            return {"ok": True, "status": "rejected"}

    def list_pending(self):
        with self._lock:
            now = time.time()
            out = []
            for r in list(self._requests.values()):
                if r["status"] == "pending" and now - r["created_at"] > r["timeout_sec"]:
                    r["status"] = "expired"
                out.append({
                    "id": r["id"],
                    "action": r["action"],
                    "approvals": len(r["approvals"]),
                    "required": r["required"],
                    "status": r["status"],
                })
            return [r for r in out if r["status"] == "pending"]
