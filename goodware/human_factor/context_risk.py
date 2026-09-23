"""
Goodware v3.0 - Context-aware risk scoring.
"""
from __future__ import annotations


class ContextRiskScorer:
    SEVERITY = {
        "delete_user": 0.9,
        "rotate_keys": 0.85,
        "quarantine_host": 0.7,
        "change_policy": 0.7,
        "restart_service": 0.5,
        "view_logs": 0.1,
        "default": 0.3,
    }

    def score(self, action, behavior_score=0.9):
        factors = []
        action_type = action.get("action", "default")
        base = self.SEVERITY.get(action_type, self.SEVERITY["default"])
        factors.append({"name": "action_type", "weight": 0.4, "score": base, "observed": action_type})

        loc = action.get("location", "office")
        loc_score = 0.1 if loc == "office" else (0.3 if loc == "home" else 0.7)
        factors.append({"name": "location", "weight": 0.15, "score": loc_score, "observed": loc})

        tod = action.get("time_of_day", 12)
        tod_score = 0.1 if 8 <= tod <= 18 else (0.3 if 6 <= tod <= 22 else 0.7)
        factors.append({"name": "time_of_day", "weight": 0.1, "score": tod_score, "observed": tod})

        dev = action.get("device_id", "known")
        dev_score = 0.1 if dev == "known" else 0.6
        factors.append({"name": "device", "weight": 0.15, "score": dev_score, "observed": dev})

        beh_score = 1.0 - behavior_score
        factors.append({"name": "behavior", "weight": 0.2, "score": beh_score, "observed": round(behavior_score, 2)})

        risk = min(1.0, sum(f["weight"] * f["score"] for f in factors))
        rationale = ", ".join(f'{f["name"]}={f["observed"]}' for f in factors)
        return {"risk": risk, "factors": factors, "rationale": rationale}
