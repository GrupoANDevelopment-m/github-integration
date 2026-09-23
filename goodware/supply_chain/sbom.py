"""Goodware v3.0 - SBOM (Software Bill of Materials)."""
from __future__ import annotations
import hashlib
import json
import os
import time


class SBOMManager:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def exists(self):
        return os.path.exists(self.path)

    def load(self):
        if not self.exists():
            return {"bomFormat": "CycloneDX-lite", "specVersion": "1.5", "components": []}
        try:
            with open(self.path) as f:
                return json.load(f)
        except Exception:
            return {"components": []}

    def save(self, sbom):
        sbom["timestamp"] = time.time()
        with open(self.path, "w") as f:
            json.dump(sbom, f, indent=2)

    def generate(self, paths):
        sbom = {"bomFormat": "CycloneDX-lite", "specVersion": "1.5", "components": []}
        for root in paths:
            if not os.path.exists(root):
                continue
            for dp, _, files in os.walk(root):
                if any(skip in dp for skip in ("__pycache__", ".git", "node_modules", ".venv")):
                    continue
                for fn in files:
                    if fn.endswith((".pyc", ".log", ".tmp", ".bin")):
                        continue
                    fp = os.path.join(dp, fn)
                    try:
                        with open(fp, "rb") as f:
                            data = f.read()
                        sha = hashlib.sha256(data).hexdigest()
                        sbom["components"].append({
                            "type": "file",
                            "name": fn,
                            "version": "1.0",
                            "source": fp,
                            "sha256": sha,
                        })
                    except Exception:
                        pass
        self.save(sbom)
        return sbom

    def add_component(self, name, version, source, sha256):
        sbom = self.load()
        sbom["components"].append({
            "type": "module",
            "name": name,
            "version": version,
            "source": source,
            "sha256": sha256,
        })
        self.save(sbom)

    def verify(self):
        sbom = self.load()
        results = {"verified": 0, "failed": 0, "findings": []}
        for c in sbom.get("components", []):
            src = c.get("source")
            sha_expected = c.get("sha256")
            if not src or not os.path.exists(src):
                results["findings"].append({"component": c.get("name"), "issue": "missing"})
                results["failed"] += 1
                continue
            try:
                with open(src, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
                if sha == sha_expected:
                    results["verified"] += 1
                else:
                    results["findings"].append({"component": c.get("name"), "issue": "hash_mismatch", "expected": sha_expected[:12], "actual": sha[:12]})
                    results["failed"] += 1
            except Exception as e:
                results["findings"].append({"component": c.get("name"), "issue": str(e)})
                results["failed"] += 1
        return results
