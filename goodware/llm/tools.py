"""
Goodware v3.0 — Tool definitions para o LLM.

O LLM pode chamar estas tools. Cada tool tem:
- name: identificador
- description: o que faz
- parameters: schema JSON dos argumentos
- run(): função que executa a tool

Lista de tools (whitelist):
- quarantine_path: quarentenar ficheiro
- kill_process: matar processo
- nft_block_ip: bloquear IP no firewall
- scan_rootkit: correr rootkit detector
- scan_cis: correr CIS benchmark
- get_pqc_status: estado do PQC
- list_suspicious_processes: processos suspeitos
- report_incident: enviar para log de incidentes
"""
from __future__ import annotations
import json
from typing import Dict, List, Any


TOOLS = [
    {
        "name": "quarantine_path",
        "description": "Move um ficheiro para a quarentena (chmod 000) e bloqueia.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Caminho absoluto do ficheiro"},
                "reason": {"type": "string", "description": "Razão da quarentena"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "kill_process",
        "description": "Envia SIGKILL a um processo (use apenas se confirmado malicioso).",
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "PID do processo"},
                "tree": {"type": "boolean", "description": "Matar também processos filhos", "default": False},
            },
            "required": ["pid"],
        },
    },
    {
        "name": "nft_block_ip",
        "description": "Adiciona regra nftables para bloquear tráfego de/para um IP.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Endereço IP"},
                "direction": {"type": "string", "enum": ["src", "dst"], "default": "src"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "scan_rootkit",
        "description": "Corre o detector de rootkits.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "scan_cis",
        "description": "Corre o CIS Benchmark.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "get_pqc_status",
        "description": "Retorna estado da criptografia pós-quântica (liboqs).",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "list_suspicious_processes",
        "description": "Lista processos com comportamentos suspeitos.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "report_incident",
        "description": "Regista um incidente no log.",
        "parameters": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "evidence": {"type": "object"},
            },
            "required": ["summary", "severity"],
        },
    },
]


def get_tools_for_prompt() -> str:
    """Devolve descrição das tools em texto para incluir no prompt do LLM."""
    lines = ["Tools disponíveis (use-as apenas se justificadas pelo raciocínio):", ""]
    for t in TOOLS:
        params = json.dumps(t["parameters"], ensure_ascii=False)
        lines.append(f"- **{t['name']}**: {t['description']}")
        lines.append(f"  Parâmetros: `{params}`")
        lines.append("")
    return "\n".join(lines)
