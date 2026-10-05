"""
Goodware v3.0 — Florian Roth signature-base integration wrapper.

Florian Roth's signature-base is the most comprehensive YARA + IOC
repository in the world. Used by major SOCs and incident responders.

Source: https://github.com/Neo23x0/signature-base
"""
from __future__ import annotations

import csv
import json
import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.chainsaw.signature_base")


SIGBASE_DIR = "vendor/security_tools/signature-base"
YARA_DIR = os.path.join(SIGBASE_DIR, "yara")
IOCS_DIR = os.path.join(SIGBASE_DIR, "iocs")
RULES_CSV = os.path.join(SIGBASE_DIR, "sig-base-rules.csv")


class SignatureBaseIntegration:
    """Real Florian Roth signature-base integration."""

    def __init__(self):
        self.available = os.path.isdir(SIGBASE_DIR)
        self._rules = []
        self._iocs = {"hashes": [], "c2": [], "filenames": [], "keywords": []}
        if self.available:
            self._load()

    def _load(self) -> None:
        # Load rules from CSV (fixed-column format):
        # signature;description;reference;date;score;author;category;md5
        if os.path.exists(RULES_CSV):
            try:
                with open(RULES_CSV, encoding="utf-8") as f:
                    reader = csv.reader(f, delimiter=";")
                    for row in reader:
                        if len(row) >= 8:
                            self._rules.append({
                                "signature": row[0],
                                "description": row[1],
                                "reference": row[2],
                                "date": row[3],
                                "score": row[4],
                                "author": row[5],
                                "category": row[6],
                                "md5": row[7],
                            })
                log.info(f"Loaded {len(self._rules)} rules from CSV")
            except Exception as e:
                log.warning(f"CSV load failed: {e}")
        # Load IOCs
        for ioc_type, fname in [
            ("hashes", "hash-iocs.txt"),
            ("c2", "c2-iocs.txt"),
            ("filenames", "filename-iocs.txt"),
        ]:
            fp = os.path.join(IOCS_DIR, fname)
            if os.path.exists(fp):
                try:
                    with open(fp, encoding="utf-8") as f:
                        self._iocs[ioc_type] = [
                            line.strip() for line in f
                            if line.strip() and not line.startswith("#")
                        ]
                except Exception as e:
                    log.warning(f"IOC load failed for {fname}: {e}")
        # Load keywords
        kfp = os.path.join(IOCS_DIR, "keywords.txt")
        if os.path.exists(kfp):
            try:
                with open(kfp, encoding="utf-8") as f:
                    self._iocs["keywords"] = [
                        line.strip() for line in f
                        if line.strip() and not line.startswith("#")
                    ]
            except Exception:
                pass

    def list_yara_files(self) -> List[str]:
        """List all YARA rule files."""
        if not os.path.isdir(YARA_DIR):
            return []
        return sorted([
            f for f in os.listdir(YARA_DIR)
            if f.endswith(".yar") or f.endswith(".yara")
        ])

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search by rule name or description."""
        q = query.lower()
        results = []
        for r in self._rules:
            score = 0
            if q in r.get("signature", "").lower():
                score += 5
            if q in r.get("description", "").lower():
                score += 2
            if q in r.get("category", "").lower():
                score += 3
            if score > 0:
                results.append((score, r))
        results.sort(key=lambda x: -x[0])
        return [r for _, r in results[:limit]]

    def by_category(self, category: str) -> List[Dict[str, Any]]:
        """Filter by category (e.g. APT, WEBSHELL)."""
        return [r for r in self._rules if r.get("category", "").upper() == category.upper()]

    def check_hash(self, md5: str) -> Optional[Dict[str, Any]]:
        """Check if a hash is in the IOC database."""
        for r in self._rules:
            if r.get("md5", "").lower() == md5.lower():
                return r
        return None

    def stats(self) -> Dict[str, Any]:
        return {
            "yara_files": len(self.list_yara_files()),
            "rules_in_csv": len(self._rules),
            "hash_iocs": len(self._iocs["hashes"]),
            "c2_iocs": len(self._iocs["c2"]),
            "filename_iocs": len(self._iocs["filenames"]),
            "keywords": len(self._iocs["keywords"]),
            "source": "https://github.com/Neo23x0/signature-base",
        }

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "yara_dir": YARA_DIR,
            "yara_files": len(self.list_yara_files()),
            "rules_loaded": len(self._rules),
            "iocs_loaded": sum(len(v) for v in self._iocs.values()),
            "source": "https://github.com/Neo23x0/signature-base",
        }