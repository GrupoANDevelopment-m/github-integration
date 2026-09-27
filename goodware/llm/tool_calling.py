"""
Goodware v3.0 — Tool Calling Pipeline.

Processa automaticamente tool calls nas respostas do LLM:
1. Detecta marcadores de tool call no texto
2. Faz parse dos parâmetros (JSON ou XML)
3. Executa a tool real (não mock)
4. Substitui marcador pelo resultado
5. Re-submete ao LLM para integração

Formatos suportados:
- Anthropic-style XML: <tool_use name="..."><input>{...}</input></tool_use>
- JSON function calling: {"name": "...", "parameters": {...}}
- Markdown code blocks: ```tool_call\n{...}\n```
- ReAct style: Action: tool_name(arg1=val1)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from . import tools

log = logging.getLogger("goodware.llm.tool_calling")


class ToolCall:
    """Representa uma tool call extraída da resposta do LLM."""

    def __init__(self, name: str, parameters: Dict[str, Any], raw: str = ""):
        self.name = name
        self.parameters = parameters
        self.raw = raw

    def execute(self) -> Dict[str, Any]:
        """Executa a tool via registry."""
        return tools.execute_tool(self.name, self.parameters)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "parameters": self.parameters, "raw": self.raw}


def parse_tool_calls(text: str) -> List[ToolCall]:
    """Detecta e extrai tool calls de uma resposta de LLM.

    Suporta 4 formatos:
    1. XML Anthropic: <tool_use name="kill_process"><pid>4242</pid></tool_use>
    2. JSON function calling: {"name": "kill_process", "parameters": {"pid": 4242}}
    3. Markdown: ```tool_call\n{"name": "kill_process", ...}\n```
    4. ReAct: Action: kill_process(pid=4242)
    """
    calls = []

    # Formato 1: XML Anthropic
    xml_pattern = r'<tool_use\s+name="([^"]+)"[^>]*>(.*?)</tool_use>'
    for match in re.finditer(xml_pattern, text, re.DOTALL):
        name = match.group(1)
        body = match.group(2)
        # Tentar JSON
        try:
            params = json.loads(body)
        except Exception:
            # Tentar XML-like <key>value</key>
            params = {}
            for kv in re.finditer(r'<(\w+)>([^<]*)</\1>', body):
                params[kv.group(1)] = kv.group(2)
        calls.append(ToolCall(name, params, match.group(0)))

    # Formato 2: JSON function calling (object isolado)
    json_pattern = r'\{[^{}]*"name"\s*:\s*"(\w+)"[^{}]*"parameters"\s*:\s*(\{[^{}]*\})[^{}]*\}'
    for match in re.finditer(json_pattern, text):
        name = match.group(1)
        try:
            params = json.loads(match.group(2))
        except Exception:
            params = {}
        calls.append(ToolCall(name, params, match.group(0)))

    # Formato 3: Markdown
    md_pattern = r'```tool_call\s*\n(.*?)\n```'
    for match in re.finditer(md_pattern, text, re.DOTALL):
        try:
            obj = json.loads(match.group(1))
            name = obj.get("name") or obj.get("tool") or obj.get("function")
            params = obj.get("parameters") or obj.get("params") or obj.get("arguments") or {}
            if name:
                calls.append(ToolCall(name, params, match.group(0)))
        except Exception:
            pass

    # Formato 4: ReAct style
    react_pattern = r'Action:\s*(\w+)\(([^)]*)\)'
    for match in re.finditer(react_pattern, text):
        name = match.group(1)
        args_str = match.group(2)
        params = _parse_kwargs(args_str)
        calls.append(ToolCall(name, params, match.group(0)))

    return calls


def _parse_kwargs(s: str) -> Dict[str, Any]:
    """Parse key=value pairs."""
    params = {}
    # Match key=value, key="value", key='value'
    pattern = r'(\w+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\d+(?:\.\d+)?|true|false|null|\[[^\]]*\]|\{[^{}]*\}))'
    for m in re.finditer(pattern, s):
        key = m.group(1)
        val = m.group(2) or m.group(3) or m.group(4) or ""
        # Type cast
        if val == "true": val = True
        elif val == "false": val = False
        elif val == "null": val = None
        elif val and val.replace(".", "").replace("-", "").isdigit():
            val = float(val) if "." in val else int(val)
        elif val.startswith("[") or val.startswith("{"):
            try: val = json.loads(val)
            except: pass
        params[key] = val
    return params


def execute_tool_calls_in_text(text: str, max_iterations: int = 5) -> str:
    """Processa tool calls na resposta e devolve texto com resultados integrados.

    Implementa loop: detecta tool calls → executa → substitui por resultados → re-processa.
    """
    iterations = 0
    current = text

    while iterations < max_iterations:
        calls = parse_tool_calls(current)
        if not calls:
            break

        log.info(f"Tool calls detected: {[c.name for c in calls]}")

        # Executar todas as tool calls
        results = []
        for call in calls:
            result = call.execute()
            log.info(f"Tool {call.name}({call.parameters}) → {result}")
            results.append({
                "name": call.name,
                "parameters": call.parameters,
                "result": result,
            })

        # Substituir tool calls por resultados
        for call in reversed(calls):
            # Encontrar o resultado correspondente
            matching = [r for r in results if r["name"] == call.name]
            if matching:
                result_json = json.dumps(matching[0]["result"], ensure_ascii=False, indent=2)
                replacement = f"<tool_result name=\"{call.name}\">\n```json\n{result_json}\n```\n</tool_result>"
                current = current.replace(call.raw, replacement, 1)
            else:
                current = current.replace(call.raw, f"<tool_error name=\"{call.name}\">no result</tool_error>", 1)

        iterations += 1

    return current


def tool_call_loop(prompt: str, adapter, system_prompt: str = None,
                   session_id: str = None, max_iterations: int = 3) -> Dict[str, Any]:
    """Loop completo: prompt → LLM → tool calls → executar → LLM novamente.

    Returns:
        {
            "iterations": int,
            "final_response": str,
            "tool_calls": [list of all calls],
            "results": [list of all results]
        }
    """
    all_calls = []
    all_results = []
    current_prompt = prompt
    final_response = ""
    iterations = 0

    while iterations < max_iterations:
        result = adapter.run(current_prompt, system_prompt=system_prompt, session_id=session_id)
        final_response = result.final_response
        iterations += 1

        calls = parse_tool_calls(final_response)
        if not calls:
            break

        for call in calls:
            tr = call.execute()
            all_calls.append(call.to_dict())
            all_results.append({"name": call.name, "parameters": call.parameters, "result": tr})

        # Substituir no texto
        processed = execute_tool_calls_in_text(final_response)

        # Próximo prompt inclui os resultados
        current_prompt = (
            f"Continua com base nos resultados das tools. Aqui está o que executei:\n\n"
            f"```\n{processed}\n```\n\n"
            "Agora integra os resultados e responde de forma completa em português de Portugal."
        )

    return {
        "iterations": iterations,
        "final_response": final_response,
        "tool_calls": all_calls,
        "results": all_results,
    }
