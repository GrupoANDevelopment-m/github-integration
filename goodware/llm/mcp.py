"""
Goodware v3.0 — MCP (Model Context Protocol) support.

Permite ao Harness descobrir e usar servers MCP externos.
Cada MCP server expõe tools adicionais via protocolo JSON-RPC.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.llm.mcp")


MCP_CONFIG_PATH = Path("/workspace/goodware-v3/config/mcp_servers.json")


class MCPServer:
    """Representa um MCP server registado."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.command = config.get("command")
        self.args = config.get("args", [])
        self.env = config.get("env", {})
        self.description = config.get("description", "")
        self.tools = config.get("tools", [])
        self._proc: Optional[subprocess.Popen] = None
        self._running = False

    def start(self) -> bool:
        if self._running:
            return True
        if not self.command:
            return False
        try:
            env = {**os.environ, **self.env}
            self._proc = subprocess.Popen(
                [self.command] + self.args,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self._running = True
            log.info(f"MCP server {self.name} started (PID={self._proc.pid})")
            return True
        except Exception as e:
            log.warning(f"Failed to start MCP server {self.name}: {e}")
            return False

    def stop(self) -> None:
        if self._proc and self._running:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                self._proc.kill()
            self._running = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tools": self.tools,
            "running": self._running,
        }


class MCPRegistry:
    """Registo de MCP servers."""

    def __init__(self, config_path: Optional[Path] = None):
        self._path = config_path or MCP_CONFIG_PATH
        self._servers: Dict[str, MCPServer] = {}
        self.reload()

    def reload(self) -> None:
        self._servers.clear()
        if not self._path.exists():
            return
        try:
            config = json.loads(self._path.read_text())
            for name, srv in config.get("servers", {}).items():
                self._servers[name] = MCPServer(name, srv)
        except Exception as e:
            log.warning(f"Falha a ler MCP config: {e}")

    def add(self, name: str, command: str, args: List[str] = None,
            env: Dict[str, str] = None, description: str = "",
            tools: List[str] = None) -> None:
        cfg = {
            "command": command,
            "args": args or [],
            "env": env or {},
            "description": description,
            "tools": tools or [],
        }
        self._servers[name] = MCPServer(name, cfg)
        self._save()

    def remove(self, name: str) -> bool:
        if name in self._servers:
            self._servers[name].stop()
            del self._servers[name]
            self._save()
            return True
        return False

    def get(self, name: str) -> Optional[MCPServer]:
        return self._servers.get(name)

    def list(self) -> List[MCPServer]:
        return list(self._servers.values())

    def start_all(self) -> int:
        n = 0
        for s in self._servers.values():
            if s.start():
                n += 1
        return n

    def stop_all(self) -> None:
        for s in self._servers.values():
            s.stop()

    def all_tools(self) -> List[Dict[str, Any]]:
        """Lista todas as tools expostas pelos MCP servers."""
        tools = []
        for s in self._servers.values():
            for tool in s.tools:
                tools.append({"name": tool, "server": s.name})
        return tools

    def _save(self) -> None:
        config = {"servers": {}}
        for name, s in self._servers.items():
            config["servers"][name] = {
                "command": s.command,
                "args": s.args,
                "env": s.env,
                "description": s.description,
                "tools": s.tools,
            }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(config, indent=2))


_registry: Optional[MCPRegistry] = None


def get_mcp_registry() -> MCPRegistry:
    global _registry
    if _registry is None:
        _registry = MCPRegistry()
    return _registry
