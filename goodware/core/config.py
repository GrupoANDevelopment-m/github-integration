"""
Goodware v3.0 - Configuração
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "general": {
        "data_dir": "data",
        "log_dir": "logs",
        "log_level": "INFO",
        "node_id": "goodware-node-001",
        "organization": "default",
    },
    "sensors": {
        "filesystem": {
            "enabled": True,
            "watch_paths": ["/etc", "/usr/local/bin", "/usr/bin", "/tmp"],
            "ignore_patterns": [".*\\.log$", ".*~$"],
        },
        "process": {
            "enabled": True,
            "scan_interval_sec": 5,
            "suspicious_names": [
                "nc", "ncat", "netcat", "miner", "xmrig",
                "kdevtmpfsi", "cryptominer", "mirai", "tsunami",
            ],
            "suspicious_paths": ["/tmp", "/dev/shm", "/var/tmp"],
        },
        "network": {
            "enabled": True,
            "scan_interval_sec": 10,
            "monitor_ports": [22, 80, 443, 3389, 4444, 5555, 6666, 8080, 8443, 9001],
            "alert_on_new_listener": True,
        },
        "config": {
            "enabled": True,
            "watch_files": ["/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab"],
        },
        "behavior": {
            "enabled": True,
            "track_logins": True,
            "track_privilege_escalation": True,
        },
    },
    "prediction": {
        "enabled": True,
        "horizon_hours": 24,
        "model_dir": "models",
        "retrain_interval_hours": 6,
    },
    "federated": {
        "enabled": True,
        "server_url": "http://127.0.0.1:8443",
        "node_secret": "change-me-in-production",
        "push_interval_sec": 300,
    },
    "crypto": {
        "default_algorithm": "kyber512",
        "key_dir": "keys",
        "hybrid": True,
        "rotation_days": 30,
    },
    "human_factor": {
        "behavioral_biometrics": True,
        "context_risk_threshold": 0.7,
        "multi_party_threshold": 0.9,
        "out_of_band": {
            "enabled": False,
            "channel": "log",  # log | telegram | email
        },
    },
    "physical": {
        "memory_encryption": True,
        "dma_prevention": True,
        "attestation_interval_min": 60,
    },
    "supply_chain": {
        "sbom_path": "sbom/sbom.json",
        "signatures_dir": "signatures",
        "verify_on_start": True,
    },
    "immune": {
        "auto_evolve": True,
        "mutation_detection": True,
        "zero_day_prediction": True,
    },
    "decision": {
        "risk_thresholds": {"low": 0.3, "medium": 0.55, "high": 0.75, "critical": 0.9},
        "human_in_loop_above": 0.85,
    },
    "effector": {
        "auto_quarantine": True,
        "auto_rollback": True,
        "firewall_backend": "internal",  # internal | iptables
    },
    "api": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8444,
    },
    "dashboard": {
        "enabled": True,
        "port": 8080,
    },
}


@dataclass
class GoodwareConfig:
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "GoodwareConfig":
        cfg = {k: _deep_copy(v) for k, v in DEFAULT_CONFIG.items()}
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                user = yaml.safe_load(f) or {}
            cfg = _deep_merge(cfg, user)
        return cls(raw=cfg)

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = self.raw
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value

    def as_dict(self) -> Dict[str, Any]:
        return self.raw


def _deep_copy(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _deep_copy(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_deep_copy(x) for x in d]
    return d


def _deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = _deep_copy(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = _deep_copy(v)
    return out
