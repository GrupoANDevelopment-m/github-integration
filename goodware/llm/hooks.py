"""
Goodware v3.0 — Hooks System.

Permite interceptar eventos do runtime do Harness:
- pre_run: antes de enviar prompt ao LLM
- post_run: depois de receber resposta
- pre_tool_call: antes de executar tool
- post_tool_call: depois de executar tool
- on_error: em caso de erro

Cada hook pode:
- Modificar o input/output
- Cancelar a operação
- Adicionar metadados
- Disparar side-effects (logging, alerting)

Formato:
```python
@hook("pre_tool_call")
def validate_block_ip(call):
    if call.parameters.get("ip") == "127.0.0.1":
        return HookResult(block=True, reason="localhost not allowed")
    return HookResult.ok()
```
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("goodware.llm.hooks")


@dataclass
class HookResult:
    """Resultado de um hook."""
    block: bool = False
    modified_input: Optional[Any] = None
    modified_output: Optional[Any] = None
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(cls) -> "HookResult":
        return cls()

    @classmethod
    def block_with(cls, reason: str) -> "HookResult":
        return cls(block=True, reason=reason)


@dataclass
class HookContext:
    """Contexto passado aos hooks."""
    event_type: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class HooksRegistry:
    """Registo global de hooks."""

    def __init__(self):
        self._hooks: Dict[str, List[Callable]] = {
            "pre_run": [],
            "post_run": [],
            "pre_tool_call": [],
            "post_tool_call": [],
            "on_error": [],
            "on_session_start": [],
            "on_session_end": [],
        }
        self._lock = threading.RLock()

    def register(self, event_type_or_func=None, callback: Callable = None) -> Any:
        """Regista callback para um tipo de evento. Suporta decorator."""
        # Modo decorator: @reg.register
        if callable(event_type_or_func) and callback is None:
            func = event_type_or_func
            # Determinar event_type do nome
            event_type = "pre_run"  # default — pode ser melhorado
            self._do_register(event_type, func)
            return func
        # Modo funcional: reg.register("event_type", callback)
        event_type = event_type_or_func
        return self._do_register(event_type, callback)

    def _do_register(self, event_type: str, callback: Callable) -> Callable:
        if event_type not in self._hooks:
            self._hooks[event_type] = []
        with self._lock:
            self._hooks[event_type].append(callback)
        name = getattr(callback, "__name__", str(callback))
        log.info(f"Hook registered: {event_type} → {name}")
        return callback

    def unregister(self, event_type: str, callback: Callable) -> bool:
        """Remove callback."""
        if event_type not in self._hooks:
            return False
        with self._lock:
            if callback in self._hooks[event_type]:
                self._hooks[event_type].remove(callback)
                return True
        return False

    def trigger(self, event_type: str, ctx: HookContext) -> HookResult:
        """Dispara hooks para um evento. Primeiro hook que bloquear termina."""
        if event_type not in self._hooks:
            return HookResult.ok()
        with self._lock:
            callbacks = list(self._hooks[event_type])
        for cb in callbacks:
            try:
                result = cb(ctx)
                if isinstance(result, HookResult):
                    if result.block:
                        log.info(f"Hook {cb.__name__} blocked {event_type}: {result.reason}")
                        return result
                    # Modificar input/output se pedido
                    if result.modified_input is not None:
                        ctx.metadata["modified_input"] = result.modified_input
                    if result.modified_output is not None:
                        ctx.metadata["modified_output"] = result.modified_output
            except Exception as e:
                log.warning(f"Hook {cb.__name__} errored: {e}")
        return HookResult.ok()

    def list_hooks(self) -> Dict[str, List[str]]:
        """Lista callbacks por evento."""
        with self._lock:
            return {k: [c.__name__ for c in v] for k, v in self._hooks.items()}


# Singleton
_registry: Optional[HooksRegistry] = None
_lock = threading.Lock()


def get_hooks_registry() -> HooksRegistry:
    global _registry
    with _lock:
        if _registry is None:
            _registry = HooksRegistry()
            _register_default_hooks(_registry)
        return _registry


def _register_default_hooks(reg: HooksRegistry) -> None:
    """Hooks por defeito que vêm com o Goodware."""

    def validate_block_ip(ctx: HookContext) -> HookResult:
        """Não bloquear localhost ou IPs privados."""
        params = ctx.metadata.get("parameters", {})
        ip = params.get("ip", "")
        if ip in ("127.0.0.1", "0.0.0.0", "::1") or ip.startswith("10.") or ip.startswith("192.168."):
            if ip not in params.get("_allowed", []):
                return HookResult.block_with(f"Refusing to block private/local IP {ip}")
        return HookResult.ok()

    def validate_kill_protected(ctx: HookContext) -> HookResult:
        """Não matar processos críticos."""
        params = ctx.metadata.get("parameters", {})
        pid = params.get("pid")
        if pid:
            try:
                import psutil
                p = psutil.Process(pid)
                cmdline = " ".join(p.cmdline() or [])
                protected = ["systemd", "init", "sshd", "kthreadd", "goodware"]
                for prot in protected:
                    if prot in cmdline:
                        return HookResult.block_with(f"Refusing to kill protected process {prot} (pid={pid})")
            except Exception:
                pass
        return HookResult.ok()

    def audit_tool_call(ctx: HookContext) -> HookResult:
        """Escreve cada tool call no log de auditoria."""
        log_path = Path("/workspace/goodware-v3/logs/tool_audit.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps({
                    "timestamp": ctx.timestamp,
                    "name": ctx.metadata.get("name"),
                    "params": ctx.metadata.get("parameters"),
                    "result_ok": "error" not in str(ctx.metadata.get("result", "")),
                }) + "\n")
        except Exception as e:
            log.warning(f"audit_tool_call error: {e}")
        return HookResult.ok()

    def on_error_alert(ctx: HookContext) -> HookResult:
        """Em erro, escrever para log estruturado."""
        log.warning(f"Harness error: {ctx.metadata}")
        return HookResult.ok()

    reg._do_register("pre_tool_call", validate_block_ip)
    reg._do_register("pre_tool_call", validate_kill_protected)
    reg._do_register("post_tool_call", audit_tool_call)
    reg._do_register("on_error", on_error_alert)
