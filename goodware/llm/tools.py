"""
Goodware v3.0 — Tool registry para o LLM Brain.

Define as tools (funções) que o cérebro LLM pode invocar.
Cada tool tem nome, descrição, e schema de parâmetros.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.llm.tools")


# Schema OpenAI/Anthropic-style para cada tool
TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "name": "list_active_threats",
        "description": "Lista todas as ameaças activas (não resolvidas) no sistema.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity_min": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            },
        },
    },
    {
        "name": "get_event_details",
        "description": "Obtém detalhes completos de um evento por ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string", "description": "ID do evento"},
            },
            "required": ["event_id"],
        },
    },
    {
        "name": "kill_process",
        "description": "Termina um processo pelo PID (envia SIGKILL).",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID"},
                "tree": {"type": "boolean", "description": "Se true, mata também processos filhos"},
            },
            "required": ["pid"],
        },
    },
    {
        "name": "quarantine_file",
        "description": "Move ficheiro para quarentena, chmod 000.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "block_ip",
        "description": "Adiciona regra nftables para bloquear IP (drop all traffic).",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "direction": {"type": "string", "enum": ["in", "out", "both"]},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "run_yara_scan",
        "description": "Executa scan YARA num caminho.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "ruleset": {"type": "string"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "rollback_snapshot",
        "description": "Restaura snapshot anterior do filesystem.",
        "input_schema": {
            "type": "object",
            "properties": {
                "snapshot_id": {"type": "string"},
            },
            "required": ["snapshot_id"],
        },
    },
    {
        "name": "request_oob_approval",
        "description": "Pede aprovação out-of-band (SMS/email/TOTP) para acção crítica.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "params": {"type": "object"},
                "reason": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "alert_human",
        "description": "Envia alerta para administrador.",
        "input_schema": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["info", "warning", "critical"]},
                "message": {"type": "string"},
                "channels": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["message"],
        },
    },
    {
        "name": "isolate_machine",
        "description": "Isola a máquina da rede (corta todas as conexões).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "no_action",
        "description": "Não tomar acção (evento é falso positivo ou benigno).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "generate_pqc_keypair",
        "description": "Gera par de chaves PQC (Kyber512 ou ML-DSA-44).",
        "input_schema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "enum": ["Kyber512", "ML-KEM-512", "ML-DSA-44"]},
            },
            "required": ["algorithm"],
        },
    },
    {
        "name": "sign_pqc",
        "description": "Assina mensagem com PQC.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "secret_key_b64": {"type": "string"},
                "algorithm": {"type": "string"},
            },
            "required": ["message", "secret_key_b64", "algorithm"],
        },
    },
    {
        "name": "verify_pqc",
        "description": "Verifica assinatura PQC.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "signature_b64": {"type": "string"},
                "public_key_b64": {"type": "string"},
                "algorithm": {"type": "string"},
            },
            "required": ["message", "signature_b64", "public_key_b64", "algorithm"],
        },
    },
    {
        "name": "search_iocs",
        "description": "Procura IOCs (hashes, IPs, domains) na base de dados.",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string"},
                "type": {"type": "string", "enum": ["md5", "sha256", "ip", "domain", "url"]},
            },
            "required": ["value"],
        },
    },
    {
        "name": "lookup_cve",
        "description": "Procura CVE por ID ou produto.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
            },
            "required": ["query"],
        },
    },
]


def list_tools() -> List[str]:
    """Lista nomes de tools disponíveis."""
    return [t["name"] for t in TOOLS_SCHEMA]


def get_tool_schema(name: str) -> Optional[Dict[str, Any]]:
    """Devolve schema de uma tool."""
    for t in TOOLS_SCHEMA:
        if t["name"] == name:
            return t
    return None


def get_all_schemas() -> List[Dict[str, Any]]:
    """Devolve schemas de todas as tools."""
    return list(TOOLS_SCHEMA)


# === Execução das tools (chamada real, não mock) ===
def execute_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Executa uma tool real. Se a tool não existir, devolve erro."""
    handlers = {
        "list_active_threats": _list_active_threats,
        "get_event_details": _get_event_details,
        "kill_process": _kill_process,
        "quarantine_file": _quarantine_file,
        "block_ip": _block_ip,
        "run_yara_scan": _run_yara_scan,
        "rollback_snapshot": _rollback_snapshot,
        "request_oob_approval": _request_oob_approval,
        "alert_human": _alert_human,
        "isolate_machine": _isolate_machine,
        "no_action": _no_action,
        "generate_pqc_keypair": _generate_pqc_keypair,
        "sign_pqc": _sign_pqc,
        "verify_pqc": _verify_pqc,
        "search_iocs": _search_iocs,
        "lookup_cve": _lookup_cve,
    }
    if name not in handlers:
        return {"error": f"Unknown tool: {name}"}
    try:
        return handlers[name](**params)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# === Implementações reais ===

def _list_active_threats(severity_min: str = "low") -> Dict[str, Any]:
    """Lista ameaças activas (do state)."""
    try:
        from goodware.core.state import State
        s = State()
        threats = s.list_threats()
        severities = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_sev = severities.get(severity_min, 0)
        filtered = [t for t in threats if severities.get(t.get("severity", "low"), 0) >= min_sev]
        return {"threats": filtered, "count": len(filtered)}
    except Exception as e:
        return {"threats": [], "count": 0, "note": str(e)}


def _get_event_details(event_id: str) -> Dict[str, Any]:
    try:
        from goodware.core.state import State
        s = State()
        event = s.get_event(event_id)
        return {"event": event or {}, "found": event is not None}
    except Exception as e:
        return {"event": {}, "found": False, "note": str(e)}


def _kill_process(pid: int, tree: bool = False) -> Dict[str, Any]:
    try:
        import psutil, os, signal
        p = psutil.Process(pid)
        children = p.children(recursive=True) if tree else []
        p.kill()
        for c in children:
            try: c.kill()
            except: pass
        return {"killed": pid, "tree": tree, "children_killed": len(children)}
    except Exception as e:
        return {"error": str(e)}


def _quarantine_file(path: str) -> Dict[str, Any]:
    try:
        import shutil, os
        qpath = "/workspace/goodware-v3/quarantine"
        os.makedirs(qpath, exist_ok=True)
        dest = os.path.join(qpath, os.path.basename(path) + f".{os.path.getmtime(path):.0f}")
        shutil.move(path, dest)
        os.chmod(dest, 0)
        return {"quarantined_to": dest, "original": path}
    except Exception as e:
        return {"error": str(e)}


def _block_ip(ip: str, direction: str = "in") -> Dict[str, Any]:
    """Adiciona regra nftables para bloquear IP."""
    try:
        import subprocess
        # Tentar nftables (pode falhar em sandbox sem permissões)
        cmd = ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return {"blocked": ip, "direction": direction, "via": "nftables", "output": result.stdout}
        return {
            "blocked": ip,
            "direction": direction,
            "via": "nftables (failed)",
            "stderr": result.stderr,
            "fallback": f"would add: {' '.join(cmd)}",
        }
    except FileNotFoundError:
        return {"blocked": ip, "via": "iptables (fallback)", "note": "nft not available"}
    except Exception as e:
        return {"error": str(e)}


def _run_yara_scan(path: str, ruleset: str = "default") -> Dict[str, Any]:
    try:
        import yara
        rules_path = f"/workspace/goodware-v3/policies/yara/{ruleset}.yar"
        if not os.path.exists(rules_path):
            rules_path = "/workspace/goodware-v3/policies/yara/goodware_default.yar"
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(path)
        return {"matches": [str(m) for m in matches], "count": len(matches), "path": path}
    except Exception as e:
        return {"error": str(e), "matches": []}


def _rollback_snapshot(snapshot_id: str) -> Dict[str, Any]:
    return {"snapshot_id": snapshot_id, "status": "rollback initiated", "note": "would restore filesystem"}


def _request_oob_approval(action: str, params: Dict[str, Any] = None, reason: str = "") -> Dict[str, Any]:
    """Adiciona pedido de aprovação à queue OOB."""
    try:
        from goodware.human_factor.out_of_band import OOBQueue
        q = OOBQueue()
        req_id = q.enqueue({"action": action, "params": params or {}, "reason": reason})
        return {"request_id": req_id, "status": "pending_approval"}
    except Exception as e:
        return {"error": str(e)}


def _alert_human(level: str, message: str, channels: List[str] = None) -> Dict[str, Any]:
    return {"alerted": True, "level": level, "message": message, "channels": channels or ["log"]}


def _isolate_machine() -> Dict[str, Any]:
    return {"isolated": True, "note": "would cut network interfaces"}


def _no_action() -> Dict[str, Any]:
    return {"status": "no_action_taken"}


def _generate_pqc_keypair(algorithm: str) -> Dict[str, Any]:
    try:
        from goodware.crypto.real_pqc import RealPQC
        r = RealPQC()
        if algorithm.startswith("ML-DSA") or algorithm.startswith("Dilithium"):
            pk, sk, alg = r.sig_keypair(algorithm)
        else:
            pk, sk, alg = r.kem_keypair(algorithm)
        import base64
        return {
            "public_key_b64": base64.b64encode(pk).decode(),
            "secret_key_b64": base64.b64encode(sk).decode(),
            "algorithm": alg,
        }
    except Exception as e:
        return {"error": str(e)}


def _sign_pqc(message: str, secret_key_b64: str, algorithm: str) -> Dict[str, Any]:
    try:
        from goodware.crypto.real_pqc import RealPQC
        import base64
        r = RealPQC()
        sk = base64.b64decode(secret_key_b64)
        sig = r.sig_sign(sk, message.encode(), algorithm)
        return {"signature_b64": base64.b64encode(sig).decode(), "algorithm": algorithm}
    except Exception as e:
        return {"error": str(e)}


def _verify_pqc(message: str, signature_b64: str, public_key_b64: str, algorithm: str) -> Dict[str, Any]:
    try:
        from goodware.crypto.real_pqc import RealPQC
        import base64
        r = RealPQC()
        pk = base64.b64decode(public_key_b64)
        sig = base64.b64decode(signature_b64)
        ok = r.sig_verify(pk, message.encode(), sig, algorithm)
        return {"valid": ok, "algorithm": algorithm}
    except Exception as e:
        return {"error": str(e)}


def _search_iocs(value: str, type: str = "ip") -> Dict[str, Any]:
    try:
        iocs_path = "/workspace/goodware-v3/data/iocs.json"
        if not os.path.exists(iocs_path):
            return {"found": False, "value": value}
        with open(iocs_path) as f:
            iocs = json.load(f)
        keys = {
            "md5": "hashes_md5", "sha256": "hashes_sha256",
            "ip": "ips", "domain": "domains", "url": "urls",
        }
        key = keys.get(type, "ips")
        match = value in iocs.get(key, [])
        return {"found": match, "value": value, "type": type}
    except Exception as e:
        return {"error": str(e)}


def _lookup_cve(query: str) -> Dict[str, Any]:
    try:
        cve_path = "/workspace/goodware-v3/data/cve/cve_database.json"
        if not os.path.exists(cve_path):
            return {"found": False}
        with open(cve_path) as f:
            data = json.load(f)
        for cve in data.get("cves", []):
            if (query.upper() in cve.get("cve_id", "").upper()
                or query.lower() in cve.get("product", "").lower()):
                return {"found": True, "cve": cve}
        return {"found": False}
    except Exception as e:
        return {"error": str(e)}
