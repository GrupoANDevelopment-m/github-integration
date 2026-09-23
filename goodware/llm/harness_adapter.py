"""
Goodware v3.0 — Adapter oficial para o DeepSeek Harness.

Usa o Python SDK oficial `deepseek_harness` que vem no zip
`deepseek-harness-master.zip` (integrado em `goodware/llm/harness/`).

O SDK lança um subprocess `dsh-jsonrpc-agent` (TypeScript) que comunica via
JSON-RPC stdio e tem todo o sistema de plugins Cordis (subagents, tools,
sessions duráveis, compaction, etc).

Este adapter é o cérebro LLM PRIMÁRIO do Goodware.
"""
from __future__ import annotations
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

# SDK oficial — está em goodware/llm/harness/
from .harness import (
    DeepSeekHarness,
    DeepSeekHarnessConfig,
    RunResult,
    SdkProtocolError,
)


_log = logging.getLogger("goodware.llm.harness_adapter")


class HarnessAdapter:
    """Adapter entre o Goodware e o DeepSeek Harness oficial.

    Sem fallbacks. Se o Harness não estiver disponível (runtime não instalado,
    sem API key, etc.), `is_available()` retorna False e o cérebro LLM fica
    desligado. Sem mocks. Sem heurísticas. Honesto.
    """

    def __init__(self, config: Optional[DeepSeekHarnessConfig] = None):
        self.config = config or DeepSeekHarnessConfig()
        self._harness: Optional[DeepSeekHarness] = None
        self._lock = threading.RLock()
        self._sessions: Dict[str, str] = {}  # purpose → session_id
        self._stats = {
            "runs": 0,
            "tokens_in_estimate": 0,
            "tokens_out_estimate": 0,
            "errors": 0,
        }
        self._available = False
        self._init_error: Optional[str] = None

    def is_available(self) -> bool:
        """True se o Harness foi iniciado e tem runtime + API key."""
        return self._available

    def init_error(self) -> Optional[str]:
        """Mensagem de erro se o Harness não pôde ser inicializado."""
        return self._init_error

    def start(self) -> bool:
        """Lança o subprocess dsh-jsonrpc-agent e inicializa a sessão."""
        with self._lock:
            if self._available:
                return True
            try:
                self._harness = DeepSeekHarness(self.config)
                self._harness.start()
                self._available = True
                _log.info(f"DeepSeek Harness started: provider={self.config.provider} model={self.config.model}")
                return True
            except Exception as e:
                self._init_error = str(e)
                self._available = False
                self._harness = None
                _log.error(f"Failed to start DeepSeek Harness: {e}")
                return False

    def close(self) -> None:
        """Termina o subprocess."""
        with self._lock:
            if self._harness:
                try:
                    self._harness.close()
                except Exception as e:
                    _log.warning(f"Error closing harness: {e}")
                self._harness = None
            self._available = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.close()

    # ---------------- Runs (a única forma de obter LLMs reais) ----------------

    def run(
        self,
        prompt: str,
        *,
        session_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> RunResult:
        """Corre um prompt no Harness. Devolve RunResult com final_response.

        Levanta SdkProtocolError ou RuntimeError se algo correr mal.
        """
        with self._lock:
            if not self._available:
                if not self.start():
                    raise RuntimeError(f"DeepSeek Harness not available: {self._init_error}")
            try:
                # O SDK aceita lista de content blocks; se houver system_prompt,
                # prependemos como primeiro bloco text.
                content = []
                if system_prompt:
                    content.append({"type": "text", "text": system_prompt})
                content.append({"type": "text", "text": prompt})

                result = self._harness.run(
                    content,
                    session_id=session_id,
                )
                self._stats["runs"] += 1
                # estimativa grosseira: ~4 chars/token
                self._stats["tokens_in_estimate"] += len(prompt) // 4
                self._stats["tokens_out_estimate"] += len(result.final_response) // 4
                return result
            except Exception as e:
                self._stats["errors"] += 1
                _log.error(f"Harness run failed: {e}")
                raise

    def run_json(
        self,
        prompt: str,
        *,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Corre um prompt e devolve o JSON parseado do final_response.

        O LLM deve responder em JSON válido. Se não conseguir, levanta erro.
        """
        result = self.run(prompt, system_prompt=system_prompt, session_id=session_id)
        text = result.final_response.strip()
        # tentar parse direto
        try:
            return json.loads(text)
        except Exception:
            pass
        # procurar bloco JSON no texto
        import re
        m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        # fall-through: devolver raw
        return {"raw": text, "finish_reason": result.finish_reason}

    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)


# Singleton
_singleton: Optional[HarnessAdapter] = None
_singleton_lock = threading.Lock()


def get_harness() -> Optional[HarnessAdapter]:
    """Singleton thread-safe. Retorna None se o Harness não pôde iniciar.

    Usa DEEPSEEK_API_KEY / NVIDIA_API_KEY do env.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            return _singleton
        # checar env
        if not (os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("NVIDIA_API_KEY")):
            return None
        cfg = DeepSeekHarnessConfig()
        a = HarnessAdapter(cfg)
        # não iniciar automaticamente — só quando for usado
        return a


def init_harness() -> Optional[HarnessAdapter]:
    """Inicializa o Harness (subprocess). Retorna None se falhar."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            if not (os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("NVIDIA_API_KEY")):
                return None
            a = HarnessAdapter()
            if a.start():
                _singleton = a
            else:
                return None
        return _singleton


def shutdown_harness() -> None:
    """Fecha o Harness."""
    global _singleton
    with _singleton_lock:
        if _singleton:
            _singleton.close()
            _singleton = None
