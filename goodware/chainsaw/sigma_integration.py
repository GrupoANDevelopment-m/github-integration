"""
Goodware v3.0 — Sigma rule integration wrapper.

Sigma rules are the universal SIEM detection rules standard, maintained by
SigmaHQ. 3,150+ rules covering Windows, Linux, macOS, network, cloud, etc.

Source: https://github.com/SigmaHQ/sigma
Reference: https://sigmahq.io/
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.chainsaw.sigma")


SIGMA_DIR = "vendor/security_tools/sigma"
SIGMA_RULES_DIR = os.path.join(SIGMA_DIR, "rules")


class SigmaIntegration:
    """Real Sigma rules integration — loads 3,150+ detection rules."""

    def __init__(self):
        self.available = os.path.isdir(SIGMA_RULES_DIR)
        self._rules = []
        if self.available:
            self._load_rules()

    def _load_rules(self) -> None:
        """Index all Sigma rules."""
        self._rules = []
        count = 0
        for root, dirs, files in os.walk(SIGMA_RULES_DIR):
            for f in files:
                if f.endswith(".yml") and not f.startswith("_"):
                    fp = os.path.join(root, f)
                    try:
                        rule = self._parse_rule(fp)
                        if rule:
                            self._rules.append(rule)
                            count += 1
                    except Exception as e:
                        log.debug(f"Failed to parse {fp}: {e}")
        log.info(f"Loaded {count} Sigma rules from {SIGMA_RULES_DIR}")

    def _parse_rule(self, path: str) -> Optional[Dict[str, Any]]:
        """Lightweight Sigma rule parser (no PyYAML needed)."""
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return None
        rule: Dict[str, Any] = {"file": os.path.basename(path)}
        # Extract title
        m = re.search(r"^title:\s*(.+)$", content, re.MULTILINE)
        if m: rule["title"] = m.group(1).strip()
        # Description
        m = re.search(r"^description:\s*(.+)$", content, re.MULTILINE)
        if m: rule["description"] = m.group(1).strip()
        # Level (severity)
        m = re.search(r"^level:\s*['\"]?(.+?)['\"]?$", content, re.MULTILINE)
        if m: rule["level"] = m.group(1).strip()
        # Logsource category
        m = re.search(r"category:\s*['\"]?(.+?)['\"]?$", content, re.MULTILINE)
        if m: rule["category"] = m.group(1).strip()
        # Product
        m = re.search(r"^product:\s*['\"]?(.+?)['\"]?$", content, re.MULTILINE)
        if m: rule["product"] = m.group(1).strip()
        # Author
        m = re.search(r"^author:\s*['\"]?(.+?)['\"]?$", content, re.MULTILINE)
        if m: rule["author"] = m.group(1).strip()
        # UUID/ID
        m = re.search(r"^id:\s*['\"]?([a-f0-9-]+)['\"]?$", content, re.MULTILINE)
        if m: rule["id"] = m.group(1).strip()
        # Tags (mitre technique references)
        tags = re.findall(r"^tags:\s*\n((?:\s+-\s*.+\n?)+)", content, re.MULTILINE)
        if tags:
            tag_list = re.findall(r"-\s*['\"]?(.+?)['\"]?$", tags[0], re.MULTILINE)
            rule["tags"] = tag_list
        # Detection patterns count
        rule["detection"] = re.search(r"^detection:", content, re.MULTILINE) is not None
        return rule

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search Sigma rules by title, description, or tag."""
        q = query.lower()
        results = []
        for rule in self._rules:
            score = 0
            if q in rule.get("title", "").lower():
                score += 5
            if q in rule.get("description", "").lower():
                score += 2
            if any(q in str(t).lower() for t in rule.get("tags", [])):
                score += 4
            if q in rule.get("category", "").lower():
                score += 3
            if score > 0:
                results.append((score, rule))
        results.sort(key=lambda x: -x[0])
        return [r for _, r in results[:limit]]

    def by_level(self, level: str) -> List[Dict[str, Any]]:
        """Filter Sigma rules by severity level."""
        return [r for r in self._rules if r.get("level") == level]

    def by_product(self, product: str) -> List[Dict[str, Any]]:
        """Filter Sigma rules by product (windows, linux, etc)."""
        return [r for r in self._rules if r.get("product") == product]

    def stats(self) -> Dict[str, Any]:
        """Statistics about loaded Sigma rules."""
        levels = {}
        products = {}
        for r in self._rules:
            lv = r.get("level", "informational")
            levels[lv] = levels.get(lv, 0) + 1
            pd = r.get("product", "unknown")
            products[pd] = products.get(pd, 0) + 1
        return {
            "total_rules": len(self._rules),
            "by_level": levels,
            "by_product": products,
            "source": "https://github.com/SigmaHQ/sigma",
        }

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "rules_dir": SIGMA_RULES_DIR,
            "rules_loaded": len(self._rules),
            "source": "https://github.com/SigmaHQ/sigma",
        }