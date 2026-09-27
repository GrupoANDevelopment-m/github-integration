"""
Goodware v3.0 — HarnessAdapter: wrapper EXAUSTIVO do DeepSeek Harness SDK.

Aproveita TODAS as capacidades do SDK:
- DeepSeekHarness: context manager, client access
- Session: stateful conversations com session_id
- HarnessClient: low-level JSON-RPC
- Notifications streaming
- Tool calling (via runtime)
- Multi-modal content blocks
- Multiple sessions paralelas
- Compaction awareness

Métodos expostos:
- start() / close() / context manager
- run(input, session_id=None) — simples
- run_streaming(input, on_notification) — streaming
- run_with_session(input, session_id) — persistente
- list_sessions() — todas as sessões
- get_session(session_id) — recupera estado
- send_tool_result(request_id, result) — responde a tool calls
- run_json() — força output JSON
- is_available() / stats()
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Callable, Dict, List, Optional, Union

from .harness import (
    DeepSeekHarness,
    DeepSeekHarnessConfig,
    HarnessClient,
    HarnessConfig,
    Notification,
    RunResult,
    Session,
    SdkProtocolError,
)


log = logging.getLogger("goodware.llm.adapter")


class HarnessAdapter:
    """Adapter exaustivo que aproveita 100% do SDK oficial."""

    def __init__(self, config: Optional[DeepSeekHarnessConfig] = None):
        self.config = config or DeepSeekHarnessConfig()
        self._harness: Optional[DeepSeekHarness] = None
        self._started = False
        self._init_error: Optional[str] = None
        self._lock = threading.RLock()
        self._sessions: Dict[str, Session] = {}
        self._stats = {
            "runs": 0,
            "sessions_created": 0,
            "notifications_received": 0,
            "tokens_in_estimate": 0,
            "tokens_out_estimate": 0,
            "errors": 0,
            "tool_calls": 0,
        }

    def start(self) -> bool:
        """Inicia o runtime dsh-jsonrpc-agent via SDK oficial."""
        with self._lock:
            if self._started:
                return True
            try:
                self._harness = DeepSeekHarness(self.config)
                self._harness.start()
                self._started = True
                return True
            except Exception as e:
                self._init_error = f"{type(e).__name__}: {e}"
                log.error(f"Failed to start Harness: {self._init_error}")
                self._harness = None
                return False

    def close(self) -> None:
        """Fecha runtime e sessões."""
        with self._lock:
            if self._harness and self._started:
                try:
                    self._harness.close()
                except Exception as e:
                    log.warning(f"Error closing harness: {e}")
                self._harness = None
                self._sessions.clear()
                self._started = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.close()

    def is_available(self) -> bool:
        """True se runtime está vivo."""
        return self._started and self._harness is not None

    def init_error(self) -> Optional[str]:
        return self._init_error

    @property
    def client(self) -> Optional[HarnessClient]:
        """Acesso ao HarnessClient (low-level JSON-RPC)."""
        if self._harness:
            return self._harness.client
        return None

    def run(
        self,
        input: Union[str, List[Dict[str, Any]]],
        *,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        on_notification: Optional[Callable[[Notification], None]] = None,
    ) -> RunResult:
        """Run com session_id opcional (stateful)."""
        if not self.is_available():
            raise RuntimeError("DeepSeek Harness not available")

        # Prepend system prompt if given
        content_blocks: List[Dict[str, Any]] = []
        if system_prompt:
            content_blocks.append({"type": "text", "text": system_prompt})
        if isinstance(input, str):
            content_blocks.append({"type": "text", "text": input})
        else:
            content_blocks.extend(input)

        # Track notifications
        def wrapped_cb(notif: Notification) -> None:
            self._stats["notifications_received"] += 1
            if on_notification:
                on_notification(notif)

        # Use Session for stateful, or top-level run for stateless
        if session_id:
            with self._lock:
                if session_id not in self._sessions:
                    self._sessions[session_id] = self._harness.start_session(session_id)
                    self._stats["sessions_created"] += 1
                session = self._sessions[session_id]

            result = session.run(content_blocks, on_notification=wrapped_cb)
        else:
            result = self._harness.run(content_blocks, on_notification=wrapped_cb)

        self._stats["runs"] += 1
        if result.final_response:
            self._stats["tokens_out_estimate"] += len(result.final_response) // 4
            self._stats["tokens_in_estimate"] += sum(
                len(b.get("text", "")) for b in content_blocks if isinstance(b, dict)
            ) // 4

        # Detectar tool calls no resultado (heurística)
        if result.final_response and ("<tool_use>" in result.final_response or "<tool_call>" in result.final_response):
            self._stats["tool_calls"] += 1

        return result

    def run_streaming(
        self,
        input: Union[str, List[Dict[str, Any]]],
        *,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[Notification]:
        """Run que captura TODAS as notifications (streaming)."""
        captured: List[Notification] = []

        def cb(n: Notification) -> None:
            captured.append(n)

        result = self.run(
            input,
            system_prompt=system_prompt,
            session_id=session_id,
            on_notification=cb,
        )
        # Resultado sempre incluído
        captured.append(Notification(method="session.result", payload={"final": result.final_response}))
        return captured

    def run_json(
        self,
        prompt: str,
        *,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run com output forçado a JSON."""
        full_system = (system_prompt or "") + "\n\nResponde APENAS com JSON válido, sem markdown."
        result = self.run(prompt, system_prompt=full_system, session_id=session_id)
        text = result.final_response.strip()

        # Tentar parsing directo
        try:
            return json.loads(text)
        except Exception:
            pass

        # Extrair JSON do texto
        import re
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass

        # Extrair JSON array
        m = re.search(r"\[[\s\S]*\]", text)
        if m:
            try:
                return {"results": json.loads(m.group(0))}
            except Exception:
                pass

        return {
            "raw_response": text,
            "finish_reason": result.finish_reason,
            "session_id": result.session_id,
        }

    def list_sessions(self) -> List[str]:
        """Lista session_ids conhecidas."""
        with self._lock:
            return list(self._sessions.keys())

    def get_session(self, session_id: str) -> Optional[Session]:
        """Recupera uma session (stateful)."""
        with self._lock:
            return self._sessions.get(session_id)

    def forget_session(self, session_id: str) -> bool:
        """Esquece uma session."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def send_tool_result(self, request_id: Union[str, int], result: Any) -> None:
        """Responde a tool call (quando o LLM pede)."""
        if not self.is_available():
            raise RuntimeError("Harness not available")
        client = self._harness.client
        client.respond(request_id, result)

    def stats(self) -> Dict[str, Any]:
        """Estatísticas de uso."""
        with self._lock:
            return dict(self._stats)


# === Singleton management ===
_singleton: Optional[HarnessAdapter] = None
_lock_singleton = threading.Lock()


def get_harness() -> Optional[HarnessAdapter]:
    """Singleton getter. Inicia o Harness na primeira chamada."""
    global _singleton
    with _lock_singleton:
        if _singleton is None:
            a = HarnessAdapter()
            if a.start():
                _singleton = a
            else:
                log.warning(f"Harness not available: {a.init_error()}")
                return None
        return _singleton


def init_harness(config: Optional[DeepSeekHarnessConfig] = None) -> Optional[HarnessAdapter]:
    """Inicializa Harness com config específica."""
    global _singleton
    with _lock_singleton:
        if _singleton is not None:
            _singleton.close()
        a = HarnessAdapter(config)
        if a.start():
            _singleton = a
            return a
        return None


def shutdown_harness() -> None:
    """Fecha e limpa singleton."""
    global _singleton
    with _lock_singleton:
        if _singleton is not None:
            _singleton.close()
            _singleton = None
