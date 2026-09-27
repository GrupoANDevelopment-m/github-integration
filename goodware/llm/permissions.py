"""
Goodware v3.0 — Permission System.

RBAC para tools. Cada tool pode ser:
- "open": qualquer um pode chamar
- "require_role:X": requer role X
- "require_oob": requer aprovação OOB
- "admin_only": só admin

Roles:
- admin: tudo
- operator: tools normais mas não destrutivas
- viewer: só leitura
- service: para automatização

Configuração:
```python
perm = PermissionSystem()
perm.set_role("alice", "operator")
if perm.can_call("alice", "kill_process"):
    ...
```
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("goodware.llm.permissions")


PERMS_FILE = Path("/workspace/goodware-v3/config/permissions.json")


# Roles disponíveis
ROLES = {
    "admin": {
        "can": "*",  # tudo
    },
    "operator": {
        "can": [
            "list_active_threats", "get_event_details", "run_yara_scan",
            "search_iocs", "lookup_cve", "alert_human",
            "verify_pqc", "generate_pqc_keypair",
            "no_action", "isolate_machine",
        ],
        "require_oob": [
            "kill_process", "quarantine_file", "block_ip",
            "rollback_snapshot", "request_oob_approval",
        ],
    },
    "viewer": {
        "can": [
            "list_active_threats", "get_event_details", "search_iocs",
            "lookup_cve", "verify_pqc", "no_action",
        ],
    },
    "service": {
        "can": [
            "list_active_threats", "get_event_details", "run_yara_scan",
            "search_iocs", "lookup_cve", "alert_human",
            "generate_pqc_keypair", "sign_pqc", "verify_pqc",
        ],
        "require_oob": [
            "kill_process", "quarantine_file", "block_ip",
        ],
    },
}


class PermissionSystem:
    """Sistema de permissões para tools."""

    def __init__(self):
        self._user_roles: Dict[str, str] = {
            "admin": "admin",
            "operator": "operator",
            "viewer": "viewer",
            "service": "service",
            "llm": "operator",  # LLM acts as operator by default
        }
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        if PERMS_FILE.exists():
            try:
                data = json.loads(PERMS_FILE.read_text())
                if "user_roles" in data:
                    self._user_roles.update(data["user_roles"])
            except Exception as e:
                log.warning(f"Failed to load permissions: {e}")

    def _save(self) -> None:
        PERMS_FILE.parent.mkdir(parents=True, exist_ok=True)
        PERMS_FILE.write_text(json.dumps({"user_roles": self._user_roles}, indent=2))

    def set_role(self, user: str, role: str) -> None:
        with self._lock:
            self._user_roles[user] = role
            self._save()

    def get_role(self, user: str) -> Optional[str]:
        with self._lock:
            return self._user_roles.get(user)

    def can_call(self, user: str, tool: str) -> bool:
        """Verifica se user pode chamar tool."""
        role = self.get_role(user)
        if role is None:
            return False
        perms = ROLES.get(role, {})
        can = perms.get("can", [])
        if can == "*":
            return True
        if isinstance(can, list) and tool in can:
            return True
        return False

    def requires_oob(self, user: str, tool: str) -> bool:
        """Verifica se tool requer aprovação OOB."""
        role = self.get_role(user)
        if role is None:
            return False
        perms = ROLES.get(role, {})
        oob = perms.get("require_oob", [])
        if isinstance(oob, list) and tool in oob:
            return True
        return False

    def check(self, user: str, tool: str) -> Dict[str, Any]:
        """Verificação completa."""
        if not self.can_call(user, tool):
            return {"allowed": False, "reason": f"user {user} (role {self.get_role(user)}) cannot call {tool}"}
        if self.requires_oob(user, tool):
            return {"allowed": "with_oob", "reason": f"requires OOB approval"}
        return {"allowed": True}


_perms: Optional[PermissionSystem] = None


def get_permissions() -> PermissionSystem:
    global _perms
    if _perms is None:
        _perms = PermissionSystem()
    return _perms
