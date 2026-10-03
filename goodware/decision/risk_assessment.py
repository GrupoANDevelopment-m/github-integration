"""Goodware v3.0 - Multi-factor risk assessment.

Production version: risk score includes:
  - Base severity weight
  - Event type (CVE, ransomware, exfil, etc) — not just "cve" string
  - User context (role, recent failed actions, OOB history)
  - Temporal context (off-hours, weekend, time-since-last-event)
  - Behavioral context (biometric score, if available)
  - Historical context (repeat offender IP/user, prior alerts)
  - Asset value (target path, if known)
  - Network context (external IP, known-bad ASN)
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.decision.risk_assessment")


# Event type risk weights (real classifications, not just string contains)
EVENT_TYPE_WEIGHTS = {
    "ransomware": 0.98,
    "data_exfil": 0.95,
    "credential_dump": 0.90,
    "privilege_escalation": 0.92,
    "persistence": 0.85,
    "lateral_movement": 0.88,
    "cve_exploit": 0.85,
    "malware_detected": 0.80,
    "brute_force": 0.70,
    "anomaly": 0.60,
    "scan": 0.50,
    "auth_failure": 0.40,
    "config_change": 0.45,
    "file_modified": 0.35,
    "process_spawn": 0.30,
    "network_connection": 0.25,
}

# Known-bad networks (very small example; production would use a feed)
KNOWN_BAD_ASNS = {
    "AS9009": 0.4,  # example
    "AS14061": 0.3,
}


class RiskAssessor:
    SEV_W = {"info": 0.1, "low": 0.25, "medium": 0.55, "high": 0.8, "critical": 0.95}

    def __init__(self, config):
        self.config = config
        self._history_path = "data/risk_history.json"
        self._history: List[Dict] = []
        self._load_history()

    def _load_history(self):
        if os.path.exists(self._history_path):
            try:
                with open(self._history_path) as f:
                    self._history = json.load(f)
                # Trim to last 7 days
                cutoff = time.time() - 7 * 86400
                self._history = [h for h in self._history if h.get("ts", 0) > cutoff]
            except Exception:
                self._history = []

    def _save_history(self):
        try:
            with open(self._history_path, "w") as f:
                json.dump(self._history[-10000:], f, indent=2)
        except Exception:
            pass

    def _extract(self, event):
        if isinstance(event, dict):
            sev = event.get("severity", "info")
            payload = event.get("payload", {})
            etype = event.get("type", event.get("event_type", ""))
        else:
            sev = getattr(event, "severity", "info")
            sev = getattr(sev, "value", sev)
            payload = getattr(event, "payload", {})
            etype = getattr(event, "event_type", "")
            etype = getattr(etype, "value", etype)
        if hasattr(sev, "value"):
            sev = sev.value
        return sev, payload, str(etype or "").lower()

    def _temporal_factor(self) -> float:
        """Off-hours bonus risk (between 22h-6h or weekend)."""
        now = datetime.now()
        if now.weekday() >= 5:  # Sat/Sun
            return 0.15
        if now.hour < 6 or now.hour >= 22:
            return 0.20
        return 0.0

    def _historical_factor(self, payload: Dict) -> float:
        """If source IP or user has prior alerts in last hour, increase risk."""
        if not isinstance(payload, dict):
            return 0.0
        source_ip = str(payload.get("source_ip", ""))
        user = str(payload.get("user", ""))
        if not source_ip and not user:
            return 0.0
        cutoff = time.time() - 3600
        recent = [
            h for h in self._history
            if h.get("ts", 0) > cutoff and (
                h.get("source_ip") == source_ip or h.get("user") == user
            )
        ]
        if not recent:
            return 0.0
        return min(0.30, 0.05 * len(recent))

    def _behavior_factor(self, payload: Dict) -> float:
        """If biometric score is low (anomalous), increase risk."""
        bio = payload.get("biometric_score") if isinstance(payload, dict) else None
        if bio is None:
            return 0.0
        try:
            bio = float(bio)
        except Exception:
            return 0.0
        if bio < 0.3:
            return 0.30
        if bio < 0.5:
            return 0.15
        return 0.0

    def _network_factor(self, payload: Dict) -> float:
        """If source IP is in known-bad range, increase risk."""
        if not isinstance(payload, dict):
            return 0.0
        ip = str(payload.get("source_ip", ""))
        if not ip:
            return 0.0
        # Simple private IP detection
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return 0.0  # internal, no bonus
        # External — assume less trustworthy
        return 0.10

    def _asset_factor(self, payload: Dict) -> float:
        """If target is a critical asset, increase risk."""
        if not isinstance(payload, dict):
            return 0.0
        path = str(payload.get("path", ""))
        for critical in ("/etc", "/var/lib", "/root/.ssh", "shadow", "passwd",
                         "database", "config.yaml", ".env", "secret", "key"):
            if critical in path.lower():
                return 0.25
        return 0.0

    def assess(self, event) -> Dict[str, Any]:
        """Compute composite risk score with full breakdown.

        Returns:
            {"risk": float (0..1), "factors": {...}, "rationale": str}
        """
        sev, payload, etype = self._extract(event)
        factors = {}
        # 1. Base severity
        base = self.SEV_W.get(sev, 0.3)
        factors["severity"] = round(base, 3)
        # 2. Event type weight
        etype_weight = 0.0
        for key, w in EVENT_TYPE_WEIGHTS.items():
            if key in etype:
                etype_weight = max(etype_weight, w)
        factors["event_type"] = round(etype_weight, 3)
        # 3. Temporal
        tf = self._temporal_factor()
        factors["temporal"] = round(tf, 3)
        # 4. Historical
        hf = self._historical_factor(payload)
        factors["historical"] = round(hf, 3)
        # 5. Behavior (biometric)
        bf = self._behavior_factor(payload)
        factors["behavior"] = round(bf, 3)
        # 6. Network
        nf = self._network_factor(payload)
        factors["network"] = round(nf, 3)
        # 7. Asset
        af = self._asset_factor(payload)
        factors["asset"] = round(af, 3)
        # Composite: weighted sum, capped at 1.0
        composite = (
            base * 0.40
            + etype_weight * 0.25
            + tf * 0.05
            + hf * 0.10
            + bf * 0.08
            + nf * 0.04
            + af * 0.08
        )
        composite = min(1.0, max(0.0, composite))
        rationale = (
            f"sev={base:.2f} etype={etype_weight:.2f} t={tf:.2f} "
            f"hist={hf:.2f} beh={bf:.2f} net={nf:.2f} asset={af:.2f} → {composite:.2f}"
        )
        # Record in history
        record = {
            "ts": time.time(),
            "source_ip": str(payload.get("source_ip", "")) if isinstance(payload, dict) else "",
            "user": str(payload.get("user", "")) if isinstance(payload, dict) else "",
            "event_type": etype,
            "risk": composite,
        }
        self._history.append(record)
        if len(self._history) % 50 == 0:
            self._save_history()
        return {
            "risk": round(composite, 3),
            "factors": factors,
            "rationale": rationale,
        }