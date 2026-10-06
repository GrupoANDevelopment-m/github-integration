"""
Goodware v3.0 — Mandiant capa integration wrapper.

capa is the standard for identifying capabilities in executable files.
Used by FLARE (FireEye/Mandiant) for malware analysis.

Source: https://github.com/mandiant/capa
Rules: https://github.com/mandiant/capa-rules
Reference: https://mandiant.github.io/capa/
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.chainsaw.capa")


CAPA_DIR = "vendor/security_tools/capa"
CAPA_RULES_DIR = "vendor/security_tools/capa-rules"


class CapaIntegration:
    """Real Mandiant capa integration — capability detection."""

    def __init__(self):
        self.available = self._check_available()
        self.rules_available = os.path.isdir(CAPA_RULES_DIR)

    def _check_available(self) -> bool:
        if not os.path.isdir(CAPA_DIR):
            return False
        return os.path.exists(os.path.join(CAPA_DIR, "capa", "main.py"))

    def get_version(self) -> Optional[str]:
        """Get capa version."""
        try:
            with open(os.path.join(CAPA_DIR, "pyproject.toml")) as f:
                content = f.read()
            m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                return m.group(1)
        except Exception:
            pass
        # Try CHANGELOG
        try:
            with open(os.path.join(CAPA_DIR, "CHANGELOG.md")) as f:
                content = f.read()
            m = re.search(r"##\s*\[?v?(\d+\.\d+\.\d+)", content)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "unknown"

    def list_rule_categories(self) -> List[str]:
        """List capa rule categories (host-interaction, communication, etc)."""
        if not os.path.isdir(CAPA_RULES_DIR):
            return []
        cats = set()
        for root, dirs, files in os.walk(CAPA_RULES_DIR):
            # Top-level directories under capa-rules
            rel = os.path.relpath(root, CAPA_RULES_DIR)
            parts = rel.split(os.sep)
            if parts and parts[0] and not parts[0].startswith("."):
                cats.add(parts[0])
        return sorted(cats)

    def count_rules(self) -> Dict[str, int]:
        """Count rules per namespace."""
        if not os.path.isdir(CAPA_RULES_DIR):
            return {}
        counts = {}
        for root, dirs, files in os.walk(CAPA_RULES_DIR):
            for f in files:
                if f.endswith(".yml"):
                    rel = os.path.relpath(root, CAPA_RULES_DIR)
                    parts = rel.split(os.sep)
                    ns = parts[0] if parts else "unknown"
                    counts[ns] = counts.get(ns, 0) + 1
        return counts

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search capa rules by name."""
        if not os.path.isdir(CAPA_RULES_DIR):
            return []
        q = query.lower()
        results = []
        for root, dirs, files in os.walk(CAPA_RULES_DIR):
            for f in files:
                if f.endswith(".yml"):
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                        if q in f.lower() or q in content.lower():
                            m = re.search(r"^name:\s*(.+)$", content, re.MULTILINE)
                            name = m.group(1).strip() if m else f
                            m = re.search(r"^namespace:\s*(.+)$", content, re.MULTILINE)
                            ns = m.group(1).strip() if m else "unknown"
                            results.append({
                                "file": f,
                                "name": name[:100],
                                "namespace": ns,
                            })
                            if len(results) >= limit:
                                return results
                    except Exception:
                        pass
        return results

    def stats(self) -> Dict[str, Any]:
        return {
            "total_rules": sum(self.count_rules().values()),
            "rules_by_namespace": self.count_rules(),
            "source": "https://github.com/mandiant/capa",
            "rules_source": "https://github.com/mandiant/capa-rules",
        }

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "rules_available": self.rules_available,
            "version": self.get_version() if self.available else None,
            "rules_count": sum(self.count_rules().values()),
            "source": "https://github.com/mandiant/capa",
        }