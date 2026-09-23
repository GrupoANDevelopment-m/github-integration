"""
Goodware v3.0 - Real firewall integration.

Estado interno (sempre) + iptables/nftables reais (se disponíveis e com root).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Dict, List, Optional


def _have_root() -> bool:
    return os.geteuid() == 0


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


class Firewall:
    """Firewall com backend real (iptables/nftables) + estado interno sempre."""

    def __init__(self, data_dir: str = "data"):
        self.path = os.path.join(data_dir, "firewall_state.json")
        os.makedirs(data_dir, exist_ok=True)
        self.state = self._load()
        self.backend = self._detect_backend()
        self.chain = "GOODWARE"
        self.table = "filter"

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"blocked_ips": [], "blocked_ports": [], "backend": None, "rules_applied": []}

    def _save(self) -> None:
        try:
            with open(self.path, "w") as f:
                json.dump(self.state, f, indent=2)
        except Exception:
            pass

    def _detect_backend(self) -> str:
        # prefere nftables, fallback iptables
        if _have("nft"):
            return "nftables"
        if _have("iptables"):
            return "iptables"
        return "internal"

    def _run(self, args: List[str], check: bool = False) -> dict:
        """Executa comando externo. Retorna {ok, stdout, stderr, code}."""
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=10)
            return {"ok": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr, "code": r.returncode}
        except Exception as e:
            return {"ok": False, "stdout": "", "stderr": str(e), "code": -1}

    # ---- iptables real ----
    def _iptables_block_ip(self, ip: str) -> dict:
        if not _have_root():
            return {"ok": False, "reason": "not_root"}
        # cria chain se não existir
        self._run(["iptables", "-N", self.chain])
        self._run(["iptables", "-C", self.chain, "-j", "DROP"]) or \
            self._run(["iptables", "-A", self.chain, "-j", "DROP"])
        # adiciona IP
        if self._run(["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"])["code"] != 0:
            return self._run(["iptables", "-I", self.chain, "-s", ip, "-j", "DROP"])
        return {"ok": True, "already_blocked": True}

    def _iptables_unblock_ip(self, ip: str) -> dict:
        if not _have_root():
            return {"ok": False, "reason": "not_root"}
        return self._run(["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"])

    def _iptables_block_port(self, port: int, protocol: str = "tcp") -> dict:
        if not _have_root():
            return {"ok": False, "reason": "not_root"}
        # INPUT chain direct
        args = ["iptables", "-I", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"]
        if self._run(args)["ok"]:
            return {"ok": True, "applied": True}
        return {"ok": False}

    # ---- nftables real ----
    def _nft_block_ip(self, ip: str) -> dict:
        if not _have_root():
            return {"ok": False, "reason": "not_root"}
        rules = (
            "table ip goodware {\n"
            "  set blocked_ips { type ipv4_addr; flags interval; }\n"
            "  chain input { type filter hook input priority 0; policy accept;\n"
            f"    ip saddr @blocked_ips drop\n"
            "  }\n"
            "}\n"
        )
        # tenta aplicar; se já existe, ignora
        r = self._run(["nft", "-f", "-"], check=False)
        # alternativa: usar add element
        self._run(["nft", "add", "table", "ip", "goodware"])
        self._run(["nft", "add", "set", "ip", "goodware", "blocked_ips", "{", "type", "ipv4_addr", ";", "}"])
        self._run(["nft", "add", "element", "ip", "goodware", "blocked_ips", "{", ip, "}"])
        return {"ok": True, "applied": True}

    def _nft_block_port(self, port: int, protocol: str = "tcp") -> dict:
        if not _have_root():
            return {"ok": False, "reason": "not_root"}
        self._run(["nft", "add", "table", "ip", "goodware"])
        self._run(["nft", "add", "chain", "ip", "goodware", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"])
        return self._run(["nft", "add", "rule", "ip", "goodware", "input", protocol, "dport", str(port), "drop"])

    # ---- API pública ----
    def block_ip(self, ip: str, reason: str = "") -> dict:
        # sempre actualiza estado interno
        if ip not in self.state["blocked_ips"]:
            self.state["blocked_ips"].append(ip)
            self._save()
        result = {"ok": True, "ip": ip, "reason": reason, "backend": self.backend, "real_applied": False}
        # tenta aplicar real
        if self.backend == "iptables":
            r = self._iptables_block_ip(ip)
            result["iptables"] = r
            result["real_applied"] = r.get("ok", False)
        elif self.backend == "nftables":
            r = self._nft_block_ip(ip)
            result["nftables"] = r
            result["real_applied"] = r.get("ok", False)
        if not result["real_applied"]:
            result["note"] = "aplicado apenas estado interno (sem root ou backend não disponível)"
        return result

    def unblock_ip(self, ip: str) -> dict:
        if ip in self.state["blocked_ips"]:
            self.state["blocked_ips"].remove(ip)
            self._save()
        result = {"ok": True, "ip": ip, "backend": self.backend, "real_applied": False}
        if self.backend == "iptables":
            r = self._iptables_unblock_ip(ip)
            result["real_applied"] = r.get("ok", False)
        return result

    def block_port(self, port: int, protocol: str = "tcp", reason: str = "") -> dict:
        entry = {"port": port, "protocol": protocol, "reason": reason, "ts": time.time(), "real_applied": False}
        # actualiza estado
        self.state["blocked_ports"].append(entry)
        self._save()
        # tenta real
        if self.backend == "iptables":
            r = self._iptables_block_port(port, protocol)
            entry["real_applied"] = r.get("ok", False)
        elif self.backend == "nftables":
            r = self._nft_block_port(port, protocol)
            entry["real_applied"] = r.get("ok", False)
        return entry

    def is_blocked(self, ip: str) -> bool:
        return ip in self.state["blocked_ips"]

    def snapshot(self) -> dict:
        return {
            **self.state,
            "backend": self.backend,
            "root": _have_root(),
            "rules_count": len(self.state.get("rules_applied", [])),
        }

    def flush_all_goodware_rules(self) -> dict:
        """Remove todas as regras que o Goodware adicionou."""
        results = {"iptables": None, "nftables": None}
        if self.backend == "iptables" and _have_root():
            results["iptables"] = self._run(["iptables", "-F", self.chain])
            results["iptables"] = self._run(["iptables", "-X", self.chain])
        if self.backend == "nftables" and _have_root():
            results["nftables"] = self._run(["nft", "delete", "table", "ip", "goodware"])
        return results
