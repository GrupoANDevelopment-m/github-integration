"""
Goodware v3.0 — Slash Commands Registry.

Slash commands são atalhos invocáveis como /<comando> dentro de prompts.
São especialmente úteis para:
- Workflows pré-definidos
- Acesso rápido a tools
- Comandos administrativos

Cada slash command tem:
- name: nome (sem a /)
- description: o que faz
- handler: função que executa
- examples: exemplos de uso
- parameters: schema
"""
from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("goodware.llm.slash")


@dataclass
class SlashCommand:
    name: str
    description: str
    handler: Callable
    examples: List[str] = field(default_factory=list)
    parameters_schema: Dict[str, Any] = field(default_factory=dict)


class SlashCommandsRegistry:
    """Registo de slash commands."""

    def __init__(self):
        self._commands: Dict[str, SlashCommand] = {}
        self._lock = threading.RLock()
        self._register_defaults()

    def _register_defaults(self):
        """Comandos por defeito."""

        @self.register(
            name="status",
            description="Mostra estado actual do sistema Goodware",
            examples=["/status", "/status --verbose"],
        )
        def status(args: List[str], ctx: Dict[str, Any]) -> Dict[str, Any]:
            from goodware.core.engine import Engine
            from goodware.core.config import GoodwareConfig
            eng = ctx.get("engine") or Engine(GoodwareConfig())
            return {"status": eng.status()}

        @self.register(
            name="threats",
            description="Lista ameaças activas",
            examples=["/threats", "/threats --severity high"],
        )
        def threats(args: List[str], ctx: Dict[str, Any]) -> Dict[str, Any]:
            from goodware.llm.tools import execute_tool
            severity = "low"
            for i, a in enumerate(args):
                if a == "--severity" and i + 1 < len(args):
                    severity = args[i + 1]
            return execute_tool("list_active_threats", {"severity_min": severity})

        @self.register(
            name="kill",
            description="Mata um processo pelo PID",
            examples=["/kill 4242", "/kill 4242 --tree"],
        )
        def kill(args: List[str], ctx: Dict[str, Any]) -> Dict[str, Any]:
            from goodware.llm.tools import execute_tool
            if not args:
                return {"error": "usage: /kill <pid> [--tree]"}
            pid = int(args[0])
            tree = "--tree" in args
            return execute_tool("kill_process", {"pid": pid, "tree": tree})

        @self.register(
            name="quarantine",
            description="Move ficheiro para quarentena",
            examples=["/quarantine /tmp/malware"],
        )
        def quarantine(args: List[str], ctx: Dict[str, Any]) -> Dict[str, Any]:
            from goodware.llm.tools import execute_tool
            if not args:
                return {"error": "usage: /quarantine <path>"}
            return execute_tool("quarantine_file", {"path": args[0]})

        @self.register(
            name="block",
            description="Bloqueia um IP",
            examples=["/block 1.2.3.4", "/block 1.2.3.4 --in"],
        )
        def block(args: List[str], ctx: Dict[str, Any]) -> Dict[str, Any]:
            from goodware.llm.tools import execute_tool
            if not args:
                return {"error": "usage: /block <ip> [--in|--out|--both]"}
            ip = args[0]
            direction = "in"
            for i, a in enumerate(args):
                if a == "--in": direction = "in"
                elif a == "--out": direction = "out"
                elif a == "--both": direction = "both"
            return execute_tool("block_ip", {"ip": ip, "direction": direction})

        @self.register(
            name="yara",
            description="Scan YARA num caminho",
            examples=["/yara /tmp/file", "/yara /tmp/file --ruleset malware"],
        )
        def yara(args: List[str], ctx: Dict[str, Any]) -> Dict[str, Any]:
            from goodware.llm.tools import execute_tool
            if not args:
                return {"error": "usage: /yara <path> [--ruleset <name>]"}
            path = args[0]
            ruleset = "default"
            for i, a in enumerate(args):
                if a == "--ruleset" and i + 1 < len(args):
                    ruleset = args[i + 1]
            return execute_tool("run_yara_scan", {"path": path, "ruleset": ruleset})

        @self.register(
            name="help",
            description="Lista comandos disponíveis",
            examples=["/help", "/help kill"],
        )
        def help_cmd(args: List[str], ctx: Dict[str, Any]) -> Dict[str, Any]:
            if args:
                cmd = self._commands.get(args[0])
                if cmd:
                    return {
                        "name": cmd.name,
                        "description": cmd.description,
                        "examples": cmd.examples,
                    }
                return {"error": f"unknown command: {args[0]}"}
            return {
                "commands": [
                    {"name": c.name, "description": c.description, "examples": c.examples}
                    for c in self._commands.values()
                ]
            }

    def register(
        self,
        *,
        name: str,
        description: str,
        examples: List[str] = None,
        parameters_schema: Dict[str, Any] = None,
    ):
        """Decorator para registar comando."""
        def decorator(func: Callable) -> Callable:
            cmd = SlashCommand(
                name=name,
                description=description,
                handler=func,
                examples=examples or [],
                parameters_schema=parameters_schema or {},
            )
            with self._lock:
                self._commands[name] = cmd
            log.info(f"Slash command registered: /{name}")
            return func
        return decorator

    def list_commands(self) -> List[SlashCommand]:
        with self._lock:
            return list(self._commands.values())

    def get(self, name: str) -> Optional[SlashCommand]:
        with self._lock:
            return self._commands.get(name)

    def execute(self, command_line: str, ctx: Dict[str, Any] = None) -> Dict[str, Any]:
        """Executa uma slash command.

        Args:
            command_line: e.g. "/kill 4242" ou "/threats --severity high"
            ctx: contexto (engine, brain, etc.)
        """
        ctx = ctx or {}
        line = command_line.strip()
        if not line.startswith("/"):
            return {"error": "not a slash command"}

        # Parse: /<name> [args...]
        parts = line[1:].split()
        if not parts:
            return {"error": "empty command"}
        name = parts[0]
        args = parts[1:]

        cmd = self.get(name)
        if cmd is None:
            return {"error": f"unknown command: /{name}", "available": [c.name for c in self.list_commands()]}

        try:
            return cmd.handler(args, ctx)
        except Exception as e:
            log.error(f"Error in /{name}: {e}")
            return {"error": str(e)}

    def find_in_text(self, text: str) -> List[str]:
        """Encontra todas as slash commands num texto."""
        return re.findall(r"/(\w+)", text)


_registry: Optional[SlashCommandsRegistry] = None


def get_slash_commands() -> SlashCommandsRegistry:
    global _registry
    if _registry is None:
        _registry = SlashCommandsRegistry()
    return _registry
