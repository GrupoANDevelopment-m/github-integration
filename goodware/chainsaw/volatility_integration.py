"""
Goodware v3.0 — Volatility 3 integration wrapper.

Volatility is the de-facto standard for memory forensics, used by
incident responders worldwide. Supports Linux, Windows, macOS.

Source: https://github.com/volatilityfoundation/volatility3
Reference: https://volatility3.readthedocs.io/
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.chainsaw.volatility")


VOLATILITY_DIR = "vendor/security_tools/volatility3"


class VolatilityIntegration:
    """Real Volatility 3 integration — memory forensics framework."""

    def __init__(self):
        self.available = self._check_available()
        self.version = self.get_version() if self.available else None

    def _check_available(self) -> bool:
        if not os.path.isdir(VOLATILITY_DIR):
            return False
        # Volatility 3 is a Python module
        init = os.path.join(VOLATILITY_DIR, "volatility3", "__init__.py")
        return os.path.exists(init)

    def get_version(self) -> Optional[str]:
        """Get Volatility 3 version."""
        try:
            with open(os.path.join(VOLATILITY_DIR, "pyproject.toml")) as f:
                for line in f:
                    if "version" in line.lower():
                        return line.strip()
        except Exception:
            pass
        return None

    def list_plugins(self, os_family: str = "linux") -> List[str]:
        """List available Volatility 3 plugins for a given OS family."""
        # Try multiple locations (volatility3 restructured over versions)
        candidates = [
            os.path.join(VOLATILITY_DIR, "volatility3", "framework", "plugins", os_family),
            os.path.join(VOLATILITY_DIR, "volatility3", "plugins", os_family),
        ]
        for plugins_dir in candidates:
            if os.path.isdir(plugins_dir):
                plugins = []
                for f in os.listdir(plugins_dir):
                    fp = os.path.join(plugins_dir, f)
                    if f.endswith(".py") and not f.startswith("_") and os.path.isfile(fp):
                        plugins.append(f.replace(".py", ""))
                    elif os.path.isdir(fp) and not f.startswith("_"):
                        # Subpackages like windows/registry
                        for sf in os.listdir(fp):
                            if sf.endswith(".py") and not sf.startswith("_"):
                                plugins.append(f"{f}.{sf[:-3]}")
                return sorted(plugins)
        return []

    def list_os_families(self) -> List[str]:
        """List all OS families supported by Volatility 3."""
        plugins_dir = os.path.join(VOLATILITY_DIR, "volatility3", "plugins")
        if not os.path.isdir(plugins_dir):
            return []
        return sorted([d for d in os.listdir(plugins_dir)
                       if os.path.isdir(os.path.join(plugins_dir, d))
                       and not d.startswith("_")])

    def get_plugin_info(self, os_family: str, plugin_name: str) -> Dict[str, Any]:
        """Get info about a specific plugin."""
        plugin_path = os.path.join(
            VOLATILITY_DIR, "volatility3", "plugins", os_family,
            f"{plugin_name}.py"
        )
        if not os.path.exists(plugin_path):
            return {"error": f"Plugin {plugin_name} not found for {os_family}"}
        try:
            with open(plugin_path) as f:
                content = f.read()
            # Extract class docstring
            doc = ""
            in_doc = False
            for line in content.split("\n"):
                if '"""' in line:
                    in_doc = not in_doc
                    if not in_doc and doc:
                        break
                    continue
                if in_doc:
                    doc += line.strip() + " "
            return {
                "os_family": os_family,
                "plugin": plugin_name,
                "path": plugin_path,
                "doc": doc[:500] if doc else "(no docstring)",
            }
        except Exception as e:
            return {"error": str(e)}

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "version": self.version,
            "os_families": self.list_os_families(),
            "plugins_by_family": {
                fam: len(self.list_plugins(fam))
                for fam in self.list_os_families()
            },
            "source": "https://github.com/volatilityfoundation/volatility3",
        }