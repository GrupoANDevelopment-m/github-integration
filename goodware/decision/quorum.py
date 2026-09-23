"""Goodware v3.0 - Byzantine fault-tolerant quorum."""
from __future__ import annotations


class Quorum:
    def __init__(self, validators=5):
        self.validators = validators

    def decide(self, votes):
        if not votes:
            return {"decision": "pending", "votes": 0}
        approve = sum(1 for v in votes if v == "approve")
        threshold = (self.validators * 2) // 3 + 1
        return {
            "decision": "approved" if approve >= threshold else "rejected",
            "votes": len(votes),
            "approve": approve,
            "threshold": threshold,
        }
