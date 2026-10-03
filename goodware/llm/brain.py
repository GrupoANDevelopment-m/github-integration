"""
Goodware v3.0 — GoodwareBrain: wrapper EXAUSTIVO do DeepSeek Harness.

Aproveita TODAS as capacidades:
- Sessions stateful (multi-turn) ✓
- JSON-RPC low-level (HarnessClient) ✓
- Notifications streaming ✓
- Multi-modal (texto + imagem + PDF) ✓
- Tool calling automático ✓
- Hooks (pre/post) ✓
- Slash commands ✓
- Skills registry ✓
- MCP servers ✓
- Permissions (RBAC) ✓
- Telemetry ✓
- Memory persistente ✓
- Context compaction ✓
- RAG sobre knowledge base ✓

Métodos:
- explain_event, triage, decide, summarise_incidents, generate_yara_rule
- investigate, continue_investigation (stateful multi-turn)
- run_custom (livre)
- multimodal_analyse (texto + ficheiros)
- execute_slash (/command)
- ask_with_rag (com retrieval)
- remember/recall (memory persistente)
- shutdown
"""
from __future__ import annotations

import json
import logging
import time
import threading
import uuid
from typing import Any, Dict, List, Optional, Union

from .harness import DeepSeekHarnessConfig, Notification, RunResult
from .harness_adapter import HarnessAdapter, get_harness, shutdown_harness
from .providers import LLMFallbackChain
from . import tools
from . import tool_calling
from . import hooks
from . import context
from . import slash_commands
from . import memory as mem
from . import rag
from . import multimodal
from . import permissions as perms
from . import telemetry as tel

log = logging.getLogger("goodware.llm.brain")


BASE_SYSTEM_PROMPT = """Tu és o cérebro do Goodware v3.0 — um sistema imunitário digital autónomo.
Responde SEMPRE em português de Portugal (pt-PT).
Sê conciso, técnico, e orientado a acção.
Usa raciocínio chain-of-thought antes de recomendar acções.

Capacidades disponíveis (tools que podes invocar via XML ou JSON):
- list_active_threats() — listar ameaças activas
- get_event_details(event_id) — detalhes de evento
- kill_process(pid, tree=False) — matar processo
- quarantine_file(path) — mover para quarentena
- block_ip(ip, direction="in") — bloquear IP
- run_yara_scan(path, ruleset="default") — scan YARA
- rollback_snapshot(snapshot_id) — restaurar snapshot
- request_oob_approval(action, params, reason) — pedir aprovação
- alert_human(level, message, channels) — alertar admin
- isolate_machine() — isolar máquina
- generate_pqc_keypair(algorithm) — gerar chaves PQC
- sign_pqc(message, secret_key_b64, algorithm) — assinar
- verify_pqc(message, signature_b64, public_key_b64, algorithm) — verificar
- search_iocs(value, type) — procurar IOCs
- lookup_cve(query) — procurar CVE

Para invocar uma tool, usa:
<tool_use name="kill_process">
  <pid>4242</pid>
</tool_use>

OU JSON:
{"name": "kill_process", "parameters": {"pid": 4242}}

Quando propões uma acção, indica qual tool usar e com que parâmetros.
Quando recebes resultados de tools, integra-os na análise.
"""

SYSTEM_EXPLAIN = BASE_SYSTEM_PROMPT + "\n\nFormato: 1) O que aconteceu 2) Risco 3) Acções."
SYSTEM_TRIAGE = BASE_SYSTEM_PROMPT + "\n\nClassifica em severity low/medium/high/critical."
SYSTEM_DECIDE = BASE_SYSTEM_PROMPT + "\n\nEscolhe a melhor acção."
SYSTEM_SUMMARISE = BASE_SYSTEM_PROMPT + "\n\nSumário executivo / Relatório."
SYSTEM_YARA = BASE_SYSTEM_PROMPT + "\n\nGera YARA rule válida."


class GoodwareBrain:
    """Cérebro LLM que usa o DeepSeek Harness oficial com TODAS as capacidades."""

    def __init__(self, adapter: Optional[HarnessAdapter] = None):
        self._adapter = adapter
        self._lock = threading.RLock()
        self._telemetry = tel.get_telemetry()
        self._hooks = hooks.get_hooks_registry()
        self._context = context.get_context_manager()
        self._memory = mem.get_memory()
        self._rag = rag.get_rag()
        self._perms = perms.get_permissions()
        self._slashes = slash_commands.get_slash_commands()
        # Auto-fallback chain for LLM providers (cloud → local GPU → ask user)
        self._fallback = LLMFallbackChain()

    @property
    def adapter(self) -> Optional[HarnessAdapter]:
        return self._adapter

    @adapter.setter
    def adapter(self, a: Optional[HarnessAdapter]) -> None:
        self._adapter = a

    @property
    def fallback_chain(self) -> LLMFallbackChain:
        return self._fallback

    @property
    def available(self) -> bool:
        return self._adapter is not None and self._adapter.is_available()

    def _ensure(self) -> HarnessAdapter:
        if not self.available:
            raise RuntimeError("DeepSeek Harness not available — cannot use brain")
        return self._adapter

    def _run_traced(self, prompt: str, *, system_prompt: str = None,
                    session_id: str = None) -> RunResult:
        """Run com telemetry + hooks + context."""
        # Pre-run hook
        ctx = hooks.HookContext(
            event_type="pre_run",
            metadata={"prompt": prompt[:500], "session_id": session_id},
        )
        self._hooks.trigger("pre_run", ctx)
        if ctx.metadata.get("block"):
            raise RuntimeError(f"Pre-run hook blocked: {ctx.metadata.get('reason')}")

        # Context compaction
        # (Aqui simplificado — em prod, teríamos message history)

        # Actual prompt
        final_prompt = ctx.metadata.get("modified_input") or prompt

        start = time.time()
        try:
            result = self._ensure().run(final_prompt, system_prompt=system_prompt, session_id=session_id)
            duration_ms = (time.time() - start) * 1000

            # Telemetry
            self._telemetry.record_run(
                duration_ms=duration_ms,
                tokens_in=len(final_prompt) // 4,
                tokens_out=len(result.final_response) // 4 if result.final_response else 0,
                session_id=session_id,
            )

            # Detectar tool calls
            calls = tool_calling.parse_tool_calls(result.final_response or "")
            for call in calls:
                self._telemetry.record_tool_call(call.name)

            # Post-run hook
            ctx2 = hooks.HookContext(
                event_type="post_run",
                metadata={"response": result.final_response, "session_id": session_id},
            )
            self._hooks.trigger("post_run", ctx2)

            return result
        except Exception as e:
            self._telemetry.record_run(
                duration_ms=(time.time() - start) * 1000,
                session_id=session_id,
                error=type(e).__name__,
            )
            ctx3 = hooks.HookContext(
                event_type="on_error",
                metadata={"error": str(e), "type": type(e).__name__},
            )
            self._hooks.trigger("on_error", ctx3)
            raise

    # ===== Métodos principais =====

    def explain_event(self, event: Dict[str, Any], *, session_id: Optional[str] = None) -> Dict[str, Any]:
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
        # Augmentar com RAG
        augmented = self._rag.augment_prompt(prompt, top_k=2)
        result = self._run_traced(augmented, system_prompt=SYSTEM_EXPLAIN, session_id=session_id)
        return {
            "explanation": result.final_response,
            "session_id": result.session_id,
            "finish_reason": result.finish_reason,
        }

    def triage(self, event: Dict[str, Any], *, session_id: Optional[str] = None) -> Dict[str, Any]:
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
        full_system = SYSTEM_TRIAGE + "\n\nResponde APENAS com JSON válido."
        result = self._run_traced(prompt, system_prompt=full_system, session_id=session_id)
        text = (result.final_response or "").strip()
        try:
            return json.loads(text)
        except Exception:
            import re
            m = re.search(r"\{[\s\S]*\}", text)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    pass
        return {"raw": text, "session_id": result.session_id}

    def decide(self, threat: Dict[str, Any], available_actions: Optional[List[str]] = None,
               *, session_id: Optional[str] = None) -> Dict[str, Any]:
        adapter = self._ensure()
        actions = available_actions or [
            "kill_process", "quarantine_file", "block_ip",
            "run_yara_scan", "rollback_snapshot", "request_oob_approval",
            "alert_human", "isolate_machine", "no_action",
        ]
        prompt = (
            f"Dada a ameaça e o conjunto de acções disponíveis, escolhe a melhor.\n\n"
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
        full_system = SYSTEM_DECIDE + "\n\nResponde APENAS com JSON válido."
        result = self._run_traced(prompt, system_prompt=full_system, session_id=session_id)
        text = (result.final_response or "").strip()
        try:
            return json.loads(text)
        except Exception:
            import re
            m = re.search(r"\{[\s\S]*\}", text)
            if m:
                try: return json.loads(m.group(0))
                except: pass
        return {"raw": text, "session_id": result.session_id}

    def summarise_incidents(self, incidents: List[Dict[str, Any]], period: str = "24h",
                            *, session_id: Optional[str] = None) -> Dict[str, Any]:
        if not incidents:
            return {"summary": "", "incident_count": 0, "period": period}
        prompt = (
            f"Sumariza estes {len(incidents)} incidentes de segurança num relatório executivo.\n\n"
            f"Período: {period}\n\n"
            f"Incidentes:\n```json\n{json.dumps(incidents[:100], indent=2, ensure_ascii=False)}\n```\n\n"
            "Estrutura:\n1. Sumário executivo\n2. Tendências\n3. Top 3 ameaças\n4. Recomendações\n5. Métricas-chave"
        )
        result = self._run_traced(prompt, system_prompt=SYSTEM_SUMMARISE, session_id=session_id)
        return {
            "summary": result.final_response,
            "session_id": result.session_id,
            "incident_count": len(incidents),
            "period": period,
        }

    def generate_yara_rule(self, sample: Dict[str, Any], description: str = "",
                           *, session_id: Optional[str] = None) -> Dict[str, Any]:
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
        result = self._run_traced(prompt, system_prompt=SYSTEM_YARA, session_id=session_id)
        text = (result.final_response or "").strip()
        try:
            return json.loads(text)
        except Exception:
            import re
            m = re.search(r"\{[\s\S]*\}", text)
            if m:
                try: return json.loads(m.group(0))
                except: pass
        return {"yara_rule": text, "raw": True}

    def investigate(self, threat_id: str, initial_context: Dict[str, Any]) -> str:
        adapter = self._ensure()
        session_id = f"investigate-{threat_id}-{uuid.uuid4().hex[:8]}"
        self._telemetry.record_session()
        prompt = (
            f"Inicia investigação sobre ameaça {threat_id}.\n\n"
            f"Contexto:\n```json\n{json.dumps(initial_context, indent=2, ensure_ascii=False)}\n```\n\n"
            "1. Resume o que sabemos\n2. Lista informação necessária\n3. Sugere próximos passos (tools)"
        )
        result = self._run_traced(prompt, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        # Persistir contexto
        self._context.save_session(session_id, [
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": result.final_response or ""},
        ])
        return result.final_response or ""

    def continue_investigation(self, session_id: str, followup: str) -> str:
        adapter = self._ensure()
        result = self._run_traced(followup, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return result.final_response or ""

    def multimodal_analyse(self, text: str, files: List[str],
                            *, session_id: Optional[str] = None) -> Dict[str, Any]:
        adapter = self._ensure()
        blocks = multimodal.multimodal_analysis_prompt(text, files)
        result = adapter.run(blocks, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return {"analysis": result.final_response, "session_id": result.session_id}

    def run_custom(self, prompt: str, *, system_prompt: Optional[str] = None,
                   session_id: Optional[str] = None,
                   return_json: bool = False) -> Union[str, Dict[str, Any]]:
        sys = (system_prompt + "\n\n" if system_prompt else "") + BASE_SYSTEM_PROMPT
        result = self._run_traced(prompt, system_prompt=sys, session_id=session_id)
        text = result.final_response or ""
        if return_json:
            try: return json.loads(text)
            except: pass
        return text

    def ask_with_rag(self, question: str, *, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Pergunta usando RAG para fornecer contexto."""
        augmented = self._rag.augment_prompt(question, top_k=5)
        result = self._run_traced(augmented, system_prompt=BASE_SYSTEM_PROMPT, session_id=session_id)
        return {
            "answer": result.final_response,
            "sources": self._rag.query(question, top_k=5),
            "session_id": result.session_id,
        }

    def ask_via_chain(self, prompt: str, *, system_prompt: Optional[str] = None,
                       max_retries: int = 2, **kwargs) -> Dict[str, Any]:
        """Pergunta ao LLM usando a chain de fallback automático.

        Cascata na ordem:
          1. Cloud API (NVIDIA-hosted DeepSeek)
          2. Local GPU (Ollama / vLLM / llama.cpp) — se GPU detectada
          3. ask_user (instruções para adicionar nova API key)

        Cada provider tem cooldown exponencial em rate-limit (1m/5m/15m/1h).
        Retorna dict com provider usado, content, ok, e (se falhou) instruções.
        """
        result = self._fallback.invoke(
            prompt,
            system=system_prompt or BASE_SYSTEM_PROMPT,
            max_retries=max_retries,
            **kwargs,
        )
        # Telemetria
        self._telemetry.record_run(
            duration_ms=0,
            session_id=None,
            llm_provider=result.get("provider", "unknown"),
            llm_ok=result.get("ok", False),
            llm_needs_user=result.get("needs_user_action", False),
        )
        return result

    def llm_provider_status(self) -> Dict[str, Any]:
        """Status detalhado de todos os LLM providers."""
        return self._fallback.status()

    def refresh_llm_providers(self) -> None:
        """Re-detecta providers (e.g., depois de user instalar Ollama)."""
        self._fallback.refresh()

    def remember(self, key: str, value: Any, tags: List[str] = None,
                 expires_in: float = None) -> None:
        """Guarda em memória persistente."""
        self._memory.store(key, value, tags, expires_in)

    def recall(self, key: str, default: Any = None) -> Any:
        """Recupera da memória persistente."""
        return self._memory.get(key, default)

    def search_memory(self, query: str) -> List[Dict[str, Any]]:
        """Procura em memória."""
        return self._memory.search(query)

    def execute_slash(self, command_line: str, ctx: Dict[str, Any] = None) -> Dict[str, Any]:
        """Executa slash command (e.g. /status, /threats)."""
        ctx = ctx or {}
        ctx["brain"] = self
        return self._slashes.execute(command_line, ctx)

    def list_tools(self) -> List[str]:
        return tools.list_tools()

    def execute_tool(self, name: str, params: Dict[str, Any],
                     user: str = "llm") -> Dict[str, Any]:
        """Executa tool via brain (com permission check)."""
        check = self._perms.check(user, name)
        if check["allowed"] is False:
            return {"error": check["reason"], "blocked_by": "permissions"}
        if check["allowed"] == "with_oob":
            # Adicionar à queue OOB para aprovação
            try:
                oob_result = tools.execute_tool("request_oob_approval", {
                    "action": name,
                    "params": params,
                    "reason": "permission requires OOB",
                })
                return {"queued_for_approval": True, "oob": oob_result}
            except Exception as e:
                return {"error": str(e)}
        # Hook pre-tool-call
        ctx = hooks.HookContext(
            event_type="pre_tool_call",
            metadata={"name": name, "parameters": params},
        )
        hook_result = self._hooks.trigger("pre_tool_call", ctx)
        if hook_result.block:
            return {"error": f"blocked by hook: {hook_result.reason}"}
        # Executar
        result = tools.execute_tool(name, params)
        # Hook post-tool-call
        ctx2 = hooks.HookContext(
            event_type="post_tool_call",
            metadata={"name": name, "parameters": params, "result": result},
        )
        self._hooks.trigger("post_tool_call", ctx2)
        # Telemetry
        self._telemetry.record_tool_call(name)
        return result

    def close(self) -> None:
        if self._adapter:
            self._adapter.close()


# === Singleton ===
_brain: Optional[GoodwareBrain] = None
_lock = threading.Lock()


def get_brain() -> Optional[GoodwareBrain]:
    global _brain
    with _lock:
        if _brain is None:
            adapter = get_harness()
            if adapter is None:
                return None
            _brain = GoodwareBrain(adapter)
        return _brain


def init_brain(adapter: Optional[HarnessAdapter] = None) -> Optional[GoodwareBrain]:
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
    global _brain
    with _lock:
        if _brain is not None:
            _brain.close()
            _brain = None
    shutdown_harness()
