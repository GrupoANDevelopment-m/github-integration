"""
Goodware v3.0 - Real quarantine + process kill.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import uuid
from typing import Optional


def _have_root() -> bool:
    return os.geteuid() == 0


class Quarantine:
    def __init__(self, engine):
        self.engine = engine
        self.qdir = os.path.abspath(os.path.join(engine.config.get("general.data_dir", "data"), "..", "quarantine"))
        os.makedirs(self.qdir, exist_ok=True)

    def quarantine(self, path: str, reason: str, kill_pid: Optional[int] = None) -> dict:
        if not os.path.exists(path):
            return {"ok": False, "error": "not_found"}
        try:
            with open(path, "rb") as f:
                data = f.read()
            sha = hashlib.sha256(data).hexdigest()
        except Exception as e:
            return {"ok": False, "error": str(e)}
        qid = str(uuid.uuid4())[:8]
        name = os.path.basename(path)
        target = os.path.join(self.qdir, f"{sha[:16]}__{name}")
        # copiar + permissões restritas
        try:
            shutil.copy2(path, target)
            try:
                os.chmod(target, 0o000)
            except Exception:
                pass
        except Exception as e:
            return {"ok": False, "error": str(e)}
        # tentar remover o original (se for mesmo malware)
        removed = False
        try:
            if os.path.isfile(path):
                # valida o hash antes de apagar
                with open(path, "rb") as f:
                    check = hashlib.sha256(f.read()).hexdigest()
                if check == sha:
                    os.remove(path)
                    removed = True
        except Exception as e:
            removed = False
        # matar o processo se fornecido
        killed = None
        if kill_pid is not None:
            killed = self.kill_process(kill_pid)
        # persistir
        try:
            self.engine.state.add_quarantine(qid, path, sha, reason, "high")
        except Exception:
            pass
        try:
            from goodware.core.events import EventType, Severity
            self.engine.emit(
                EventType.ACTION_QUARANTINE,
                {"id": qid, "path": path, "reason": reason, "sha256": sha, "killed": killed, "removed": removed},
                severity=Severity.HIGH, source="effector",
            )
        except Exception:
            pass
        return {"ok": True, "id": qid, "quarantine_path": target, "sha256": sha,
                "killed": killed, "removed": removed, "real_actions": removed or (killed and killed.get("ok"))}

    def kill_process(self, pid: int, sig: int = signal.SIGKILL) -> dict:
        """Mata processo real com SIGKILL (default)."""
        if pid <= 0:
            return {"ok": False, "error": "invalid_pid"}
        try:
            os.kill(pid, sig)
            return {"ok": True, "pid": pid, "signal": sig, "real": True}
        except ProcessLookupError:
            return {"ok": True, "pid": pid, "already_dead": True}
        except PermissionError:
            return {"ok": False, "error": "permission_denied", "pid": pid}
        except Exception as e:
            return {"ok": False, "error": str(e), "pid": pid}

    def kill_process_tree(self, pid: int) -> dict:
        """Mata processo e filhos (via pgrep)."""
        killed = [self.kill_process(pid)]
        try:
            # encontra filhos
            out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True, timeout=3)
            for child in out.stdout.strip().split():
                if child.isdigit():
                    killed.append(self.kill_process(int(child)))
        except Exception:
            pass
        return {"ok": True, "killed": killed}

    def restore(self, qid: str, dest: Optional[str] = None) -> dict:
        """Restaura um item em quarentena para o destino (default = path original)."""
        for q in self.engine.state.list_quarantined():
            if q["id"] == qid:
                src_path = os.path.join(self.qdir, f"{q['sha256'][:16]}__{os.path.basename(q['path'])}")
                if not os.path.exists(src_path):
                    return {"ok": False, "error": "quarantine_file_missing"}
                dest = dest or q["path"]
                try:
                    shutil.copy2(src_path, dest)
                    os.chmod(dest, 0o644)
                    # marca como restaurado
                    # (simplificado: apaga do estado)
                    return {"ok": True, "restored_to": dest, "real": True}
                except Exception as e:
                    return {"ok": False, "error": str(e)}
        return {"ok": False, "error": "not_found"}
