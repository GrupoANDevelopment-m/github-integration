"""
Goodware v3.0 — MISP Galaxy integration wrapper.

MISP Galaxy is a centralized, curated knowledge base of threat actors,
malware families, attack patterns, and tools. 360+ clusters covering the
full threat landscape.

Source: https://github.com/MISP/misp-galaxy
Reference: https://www.misp-project.org/galaxy.html
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.chainsaw.misp")


GALAXY_DIR = "vendor/security_tools/misp-galaxy"
CLUSTERS_DIR = os.path.join(GALAXY_DIR, "clusters")


class MispGalaxyIntegration:
    """Real MISP Galaxy integration — loads 360+ threat intel clusters."""

    def __init__(self):
        self.available = os.path.isdir(CLUSTERS_DIR)
        self._clusters = {}
        self._index = {}  # name → cluster
        if self.available:
            self._load_clusters()

    def _load_clusters(self) -> None:
        """Index all MISP galaxy clusters."""
        self._clusters = {}
        count = 0
        for f in os.listdir(CLUSTERS_DIR):
            if f.endswith(".json"):
                fp = os.path.join(CLUSTERS_DIR, f)
                try:
                    with open(fp, encoding="utf-8") as fh:
                        data = json.load(fh)
                    name = data.get("name", f.replace(".json", ""))
                    uuid = data.get("uuid", "")
                    values = data.get("values", [])
                    cluster = {
                        "name": name,
                        "uuid": uuid,
                        "type": data.get("type", "unknown"),
                        "description": data.get("description", ""),
                        "source": data.get("source", ""),
                        "values_count": len(values),
                        "file": f,
                    }
                    self._clusters[name] = cluster
                    for v in values:
                        vname = v.get("value", "")
                        if vname:
                            self._index[vname.lower()] = v
                    count += 1
                except Exception as e:
                    log.debug(f"Failed to load {fp}: {e}")
        log.info(f"Loaded {count} MISP galaxy clusters")

    def list_clusters(self) -> List[Dict[str, Any]]:
        """List all clusters."""
        return list(self._clusters.values())

    def get_cluster(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a specific cluster by name."""
        return self._clusters.get(name)

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search for threat actors, malware, tools, etc."""
        q = query.lower()
        results = []
        seen = set()
        # Search cluster names first
        for name, cluster in self._clusters.items():
            if q in name.lower():
                results.append({"type": "cluster", **cluster})
                seen.add(name)
                if len(results) >= limit:
                    return results
        # Search values (threat actors etc)
        for key, value in self._index.items():
            if q in key and len(results) < limit:
                results.append({
                    "type": "value",
                    "value": value.get("value"),
                    "description": value.get("description", "")[:200],
                    "meta": value.get("meta", {}),
                })
        return results

    def get_threat_actor(self, name: str) -> Optional[Dict[str, Any]]:
        """Get threat actor details (e.g. 'APT1', 'Lazarus Group')."""
        for key, value in self._index.items():
            if name.lower() in key and "threat-actor" in str(value.get("meta", {})):
                return value
        return None

    def stats(self) -> Dict[str, Any]:
        """Statistics about loaded MISP Galaxy clusters."""
        by_type = {}
        total_values = 0
        for c in self._clusters.values():
            t = c.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
            total_values += c["values_count"]
        return {
            "total_clusters": len(self._clusters),
            "total_values": total_values,
            "by_type": by_type,
            "source": "https://github.com/MISP/misp-galaxy",
        }

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "clusters_dir": CLUSTERS_DIR,
            "clusters_loaded": len(self._clusters),
            "values_indexed": len(self._index),
            "source": "https://github.com/MISP/misp-galaxy",
        }