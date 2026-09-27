"""
Goodware v3.0 — GoodwareBrain: wrapper de alto nível sobre HarnessAdapter.

Aproveita TODAS as capacidades do DeepSeek Harness:
- Sessions stateful (multi-turn conversations)
- JSON-RPC via HarnessClient (low-level access)
- Notifications streaming (real-time)
- Multi-modal input (text + images)
- Tool result handling
- Multiple parallel sessions
- Compaction via long-context

Métodos:
- explain_event(event) — explica um evento em português
- triage(event) — classifica prioridade + ações
- decide(threat, actions) — escolhe acção óptima
- summarise_incidents(events, period) — sumário executiva
- generate_yara_rule(sample, desc) — gera YARA rule
- investigate(threat_id) — investigação multi-turn com session
- run_custom(prompt, session_id=None) — execução livre
- multimodal_analyse(text, image_bytes) — análise multi-modal
- shutdown()
"""
from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from typing import Any, Dict, List, Optional, Union

from .harness import DeepSeekHarnessConfig, Notification, RunResult
from .harness_adapter import HarnessAdapter, get_harness, shutdown_harness
from . import tools

log = logging.getLogger("goodware.llm.brain")


# System prompt base — comportamento do agente
BASE_SYSTEM_PROMPT = """Tu és o cérebro do Goodware v3.0 — um sistema imunitário digital autónomo.
Responde SEMPRE em português de Portugal (pt-PT).
Sê conciso, técnico, e orientado a acção.
Usa raciocínio chain-of-thought antes de recomendar acções.

Capacidades disponíveis (lista de tools que podes invocar):
- list_active_threats()
- get_event_details(event_id)
- kill_process(pid)
- quarantine_file(path)
- block_ip(ip)
- run_yara_scan(path)
- rollback_snapshot(snapshot_id)
- request_oob_approval(action)

Quando propores uma acção, indica qual tool usar e com que parâmetros.
Quando recebes resultados de tools, integra-os na análise.
"""

# Prompts específicos por método (compat com testes)
SYSTEM_EXPLAIN = BASE_SYSTEM_PROMPT + "\n\nFormato: 1) O que aconteceu 2) Risco 3) Acções."
SYSTEM_TRIAGE = BASE_SYSTEM_PROMPT + "\n\nClassifica em severity low/medium/high/critical."
SYSTEM_DECIDE = BASE_SYSTEM_PROMPT + "\n\nEscolhe a melhor acção."
SYSTEM_SUMMARISE = BASE_SYSTEM_PROMPT + "\n\nSumário executivo / Relatório."
SYSTEM_YARA = BASE_SYSTEM_PROMPT + "\n\nGera YARA rule válida."


class GoodwareBrain:
    """Cérebro LLM que usa o DeepSeek Harness oficial."""

    def __init__(self, adapter: Optional[HarnessAdapter] = None):
        self._adapter = adapter
        self._lock = threading.RLock()

    @property
    def adapter(self) -> Optional[HarnessAdapter]:
        return self._adapter

    @adapter.setter
    def adapter(self, a: Optional[HarnessAdapter]) -> None:
        self._adapter = a

    @property
    def available(self) -> bool:
        return self._adapter is not None and self._adapter.is_available()

    def _ensure(self) -> HarnessAdapter:
        if not self.available:
            raise RuntimeError("DeepSeek Harness not available — cannot use brain")
        return self._adapter

    def explain_event(self, event: Dict[str, Any], *, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Explica um evento em linguagem natural."""
        adapter = self._ensure()
        prompt = (
            "Analisa este evento de segurança e explica em português de Portugal:\n\n"
            f"```json\n{json.dumps(event, indent=2, ensure_ascii=False)}\n```\n\n"
            "Responde com:\n"
            "1. **O que aconteceu** (1 frase)\n"
            "2. **Risco** (low/medium/high/critical, com justificação)\n"
            "3. **Acções recomendadas** (lista de tools a invocar)\n"
            "4. **Contexto adicional** (se relevante)"
        )
        result = adapter.run(prompt, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return {
            "explanation": result.final_response,
            "session_id": result.session_id,
            "finish_reason": result.finish_reason,
        }

    def triage(self, event: Dict[str, Any], *, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Triage: classifica prioridade e devolve JSON."""
        adapter = self._ensure()
        prompt = (
            "Faz triage deste evento. Devolve JSON com esta forma EXACTA:\n"
            "{\n"
            '  "priority": "low"|"medium"|"high"|"critical",\n'
            '  "category": "malware"|"intrusion"|"policy_violation"|"anomaly"|"info",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "immediate_actions": [{"tool": "...", "params": {...}}],\n'
            '  "rationale": "..."\n'
            "}\n\n"
            f"```json\n{json.dumps(event, indent=2, ensure_ascii=False)}\n```"
        )
        full_system = BASE_SYSTEM_PROMPT + "\n\nResponde APENAS com JSON válido."
        return adapter.run_json(prompt, system_prompt=full_system, session_id=session_id)

    def decide(
        self,
        threat: Dict[str, Any],
        available_actions: Optional[List[str]] = None,
        *,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Decide acção óptima dada ameaça e conjunto de acções disponíveis."""
        adapter = self._ensure()
        actions = available_actions or [
            "kill_process", "quarantine_file", "block_ip",
            "run_yara_scan", "rollback_snapshot", "request_oob_approval",
            "alert_human", "isolate_machine", "no_action",
        ]
        prompt = (
            f"Dada a ameaça e o conjunto de acções disponíveis, escolhe a melhor acção.\n\n"
            f"Acções disponíveis: {actions}\n\n"
            f"Ameaça:\n```json\n{json.dumps(threat, indent=2, ensure_ascii=False)}\n```\n\n"
            "Devolve JSON:\n"
            "{\n"
            '  "chosen_action": "...",\n'
            '  "parameters": {...},\n'
            '  "reasoning": "...",\n'
            '  "alternatives": [{"action": "...", "rationale": "..."}],\n'
            '  "risk_if_no_action": "..."\n'
            "}"
        )
        full_system = BASE_SYSTEM_PROMPT + "\n\nResponde APENAS com JSON válido."
        return adapter.run_json(prompt, system_prompt=full_system, session_id=session_id)

    def summarise_incidents(
        self,
        incidents: List[Dict[str, Any]],
        period: str = "24h",
        *,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Sumariza incidentes para relatório executivo."""
        if not incidents:
            return {"summary": "", "incident_count": 0, "period": period}
        adapter = self._ensure()
        prompt = (
            f"Sumariza estes {len(incidents)} incidentes de segurança num relatório executivo em português de Portugal.\n\n"
            f"Período: {period}\n\n"
            f"Incidentes:\n```json\n{json.dumps(incidents[:100], indent=2, ensure_ascii=False)}\n```\n\n"
            "Estrutura:\n"
            "1. **Sumário executivo** (3 frases)\n"
            "2. **Tendências observadas**\n"
            "3. **Top 3 ameaças por severidade**\n"
            "4. **Recomendações** (lista priorizada)\n"
            "5. **Métricas-chave**"
        )
        result = adapter.run(prompt, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return {
            "summary": result.final_response,
            "session_id": result.session_id,
            "incident_count": len(incidents),
            "period": period,
        }

    def generate_yara_rule(
        self,
        sample: Dict[str, Any],
        description: str = "",
        *,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gera YARA rule a partir de uma sample."""
        adapter = self._ensure()
        prompt = (
            "Gera uma YARA rule em formato válido para detectar esta amostra.\n\n"
            f"Descrição: {description}\n\n"
            f"Amostra:\n```json\n{json.dumps(sample, indent=2, ensure_ascii=False)}\n```\n\n"
            "Devolve APENAS:\n"
            "{\n"
            '  "yara_rule": "rule ... { ... }",\n'
            '  "strings_used": ["..."],\n'
            '  "rationale": "..."\n'
            "}"
        )
        return adapter.run_json(prompt, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)

    def investigate(
        self,
        threat_id: str,
        initial_context: Dict[str, Any],
    ) -> str:
        """Investigação multi-turn (stateful). Cria session persistente."""
        adapter = self._ensure()
        session_id = f"investigate-{threat_id}-{uuid.uuid4().hex[:8]}"
        prompt = (
            f"Inicia uma investigação sobre a ameaça {threat_id}.\n\n"
            f"Contexto inicial:\n```json\n{json.dumps(initial_context, indent=2, ensure_ascii=False)}\n```\n\n"
            "Plano de investigação:\n"
            "1. Resume o que sabemos\n"
            "2. Lista informação que precisamos obter\n"
            "3. Sugere próximos passos (tools a usar)"
        )
        result = adapter.run(prompt, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return result.final_response

    def continue_investigation(self, session_id: str, followup: str) -> str:
        """Continua uma investigação stateful."""
        adapter = self._ensure()
        if session_id not in adapter.list_sessions():
            raise RuntimeError(f"Session {session_id} not found")
        result = adapter.run(followup, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return result.final_response

    def multimodal_analyse(
        self,
        text: str,
        image_bytes: bytes,
        *,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Análise multi-modal (texto + imagem). Suporta image_bytes."""
        adapter = self._ensure()
        content_blocks = [
            {"type": "image", "source": {"type": "base64", "data": image_bytes.hex()}},
            {"type": "text", "text": text},
        ]
        result = adapter.run(content_blocks, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return {
            "analysis": result.final_response,
            "session_id": result.session_id,
        }

    def list_tools(self) -> List[str]:
        """Lista tools que o cérebro pode invocar."""
        return tools.list_tools()

    def run_custom(
        self,
        prompt: str,
        *,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        return_json: bool = False,
    ) -> Union[str, Dict[str, Any]]:
        """Execução livre de prompt."""
        adapter = self._ensure()
        sys = (system_prompt + "\n\n" if system_prompt else "") + BASE_SYSTEM_PROMPT
        if return_json:
            return adapter.run_json(prompt, system_prompt=sys, session_id=session_id)
        result = adapter.run(prompt, system_prompt=sys, session_id=session_id)
        return result.final_response

    def close(self) -> None:
        """Fecha o adapter."""
        if self._adapter:
            self._adapter.close()


# === Singleton management ===
_brain: Optional[GoodwareBrain] = None
_lock = threading.Lock()


def get_brain() -> Optional[GoodwareBrain]:
    """Singleton brain — cria com Harness se disponível."""
    global _brain
    with _lock:
        if _brain is None:
            adapter = get_harness()
            if adapter is None:
                return None
            _brain = GoodwareBrain(adapter)
        return _brain


def init_brain(adapter: Optional[HarnessAdapter] = None) -> Optional[GoodwareBrain]:
    """Inicializa brain com adapter específico."""
    global _brain
    with _lock:
        if _brain is not None:
            _brain.close()
        if adapter is None:
            adapter = get_harness()
        if adapter is None:
            _brain = None
            return None
        _brain = GoodwareBrain(adapter)
        return _brain


def shutdown_brain() -> None:
    """Encerra brain."""
    global _brain
    with _lock:
        if _brain is not None:
            _brain.close()
            _brain = None
    shutdown_harness()
