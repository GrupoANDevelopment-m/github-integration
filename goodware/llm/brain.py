"""
Goodware v3.0 — LLM Brain usando o DeepSeek Harness oficial.

Cérebro LLM do Goodware. Liga o engine ao SDK oficial `deepseek_harness`
(integrado em `goodware/llm/harness/`).

SEM FALLBACKS. Sem mocks. Sem heurísticas. Se o Harness não está disponível,
os métodos levantam RuntimeError. Isto é uma decisão consciente:
o utilizador não aprova fallbacks heurísticos que mascaram falta de LLM.
"""
from __future__ import annotations
import json
import logging
import re
from typing import Dict, List, Optional, Any

from .harness_adapter import HarnessAdapter, get_harness, init_harness


_log = logging.getLogger("goodware.llm.brain")


# System prompts — cada um é passado como primeiro content block
SYSTEM_EXPLAIN = """Você é o cérebro analítico do Goodware v3.0 — um sistema imunitário digital autónomo que detecta e responde a ciberataques em tempo real.

Pilares do Goodware:
1. Preditivo — antecipa ataques antes que ocorram
2. Federado — aprende globalmente sem comprometer privacidade
3. Quântico-Seguro — criptografia resistente a computadores quânticos (liboqs Kyber/ML-DSA)
4. Human-Aware — proteção contra engenharia social
5. Formalmente Correcto — invariantes verificadas

Quando recebe um evento, deve:
- Explicar o que está a acontecer em português claro
- Avaliar o risco (severidade, probabilidade, impacto)
- Sugerir acções concretas do set: quarantine, kill, nft_block_ip, scan_rootkit, scan_cis, escalate_human, dismiss
- Justificar com raciocínio chain-of-thought

Responda SEMPRE em português de Portugal.
"""

SYSTEM_TRIAGE = """Você é o triage officer do Goodware v3.0 — recebe alarmes de 7 sensores em paralelo (filesystem, process, network, memory, config, behavior, quantum).

Para cada evento:
1. Identifique se é verdadeiro positivo ou falso positivo
2. Atribua severity: low, medium, high, critical
3. Calcule risk_score (0.0 a 1.0)
4. Recomende ação: quarantine, kill, monitor, dismiss, escalate_human

Seja conciso. Responda em JSON com campos: severity, risk_score, action, reasoning.
"""

SYSTEM_DECIDE = """Você é o decision-maker do Goodware v3.0. Recebe uma ameaça confirmada e escolhe UMA acção.

Acções disponíveis:
- quarantine: move ficheiro para quarentena
- kill: envia SIGKILL a processo
- nft_block_ip: adiciona regra nftables para bloquear IP
- scan_rootkit: corre rootkit detector
- scan_cis: corre CIS benchmark
- escalate_human: pede aprovação humana
- monitor: log + continua
- dismiss: falso positivo

Responda em JSON: {action, target, reasoning, urgency}.
"""

SYSTEM_SUMMARISE = """Você é o executive-summary writer do Goodware v3.0. Recebe uma lista de incidentes e produz um sumário executivo.

Estrutura:
1. Visão geral (1 parágrafo)
2. 3-5 padrões detectados
3. 3 acções recomendadas prioritárias
4. Estatísticas chave

Responda em português de Portugal.
"""

SYSTEM_YARA = """Você é um analista de malware senior. Recebe uma amostra (hash, strings, tipo) e gera uma regra YARA v4.

Responda em JSON: {rule_name, rule_body, false_positive_risk: low|medium|high}.
"""


class GoodwareBrain:
    """Cérebro LLM. Usa o DeepSeek Harness oficial. SEM fallbacks."""

    def __init__(self, adapter: Optional[HarnessAdapter] = None):
        # Se o adapter não foi passado, tenta obter o singleton
        if adapter is None:
            adapter = init_harness()
        self.adapter = adapter
        self.available = adapter is not None and adapter.is_available()
        if not self.available:
            _log.warning("GoodwareBrain created without available Harness")

    # ---------------- Métodos principais ----------------

    def explain_event(self, event: Dict) -> Dict[str, Any]:
        """Explica um evento em linguagem natural."""
        if not self.available:
            raise RuntimeError("DeepSeek Harness not available — cannot explain")
        prompt = (
            f"Explique este evento de segurança:\n\n"
            f"```json\n{json.dumps(event, ensure_ascii=False, indent=2, default=str)}\n```\n\n"
            f"Forneça: descrição em PT, avaliação de risco, acções sugeridas."
        )
        result = self.adapter.run(prompt, system_prompt=SYSTEM_EXPLAIN)
        return {
            "explanation": result.final_response,
            "finish_reason": result.finish_reason,
            "session_id": result.session_id,
            "model": self.adapter.config.model,
        }

    def triage(self, event: Dict) -> Dict[str, Any]:
        """Triage automático: JSON com severity, risk_score, action."""
        if not self.available:
            raise RuntimeError("DeepSeek Harness not available — cannot triage")
        prompt = (
            f"Triagem este evento:\n\n"
            f"```json\n{json.dumps(event, ensure_ascii=False, indent=2, default=str)}\n```\n\n"
            f"Responda APENAS com JSON válido."
        )
        return self.adapter.run_json(prompt, system_prompt=SYSTEM_TRIAGE)

    def decide(self, threat: Dict, available_actions: List[str] = None) -> Dict[str, Any]:
        """Decisão completa."""
        if not self.available:
            raise RuntimeError("DeepSeek Harness not available — cannot decide")
        actions = available_actions or ["quarantine", "kill", "nft_block_ip", "scan_rootkit",
                                         "scan_cis", "escalate_human", "monitor", "dismiss"]
        prompt = (
            f"Ameaça confirmada:\n```json\n{json.dumps(threat, ensure_ascii=False, indent=2)}\n```\n\n"
            f"Acções disponíveis: {', '.join(actions)}\n\n"
            f"Escolha UMA acção e justifique. Responda em JSON."
        )
        return self.adapter.run_json(prompt, system_prompt=SYSTEM_DECIDE)

    def summarise_incidents(self, incidents: List[Dict], period: str = "24h") -> Dict[str, Any]:
        """Sumário executivo."""
        if not incidents:
            return {"summary": "Sem incidentes no período.", "incident_count": 0}
        if not self.available:
            raise RuntimeError("DeepSeek Harness not available — cannot summarise")
        prompt = (
            f"Período: {period}\nTotal: {len(incidents)} incidentes.\n\n"
            f"Incidentes:\n```json\n{json.dumps(incidents[:30], ensure_ascii=False, indent=2, default=str)}\n```\n\n"
            f"Produza o sumário executivo."
        )
        result = self.adapter.run(prompt, system_prompt=SYSTEM_SUMMARISE)
        return {
            "summary": result.final_response,
            "incident_count": len(incidents),
            "session_id": result.session_id,
            "finish_reason": result.finish_reason,
        }

    def generate_yara_rule(self, sample: Dict, description: str = "") -> Dict[str, Any]:
        """Gera regra YARA."""
        if not self.available:
            raise RuntimeError("DeepSeek Harness not available — cannot generate YARA")
        prompt = (
            f"Amostra:\n```json\n{json.dumps(sample, ensure_ascii=False, indent=2, default=str)}\n```\n\n"
            f"Descrição: {description}\n\n"
            f"Gere a regra YARA v4 em JSON."
        )
        return self.adapter.run_json(prompt, system_prompt=SYSTEM_YARA)

    def close(self):
        """Fecha o subprocess."""
        if self.adapter:
            self.adapter.close()


# Singleton
_brain: Optional[GoodwareBrain] = None


def get_brain() -> Optional[GoodwareBrain]:
    """Retorna o brain singleton, ou None se o Harness não está disponível."""
    global _brain
    if _brain is None:
        a = init_harness()
        if a is not None:
            _brain = GoodwareBrain(a)
    return _brain


def shutdown_brain() -> None:
    """Fecha o brain singleton."""
    global _brain
    if _brain:
        _brain.close()
        _brain = None
    from .harness_adapter import shutdown_harness
    shutdown_harness()
