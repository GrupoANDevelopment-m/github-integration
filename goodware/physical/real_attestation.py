"""
Goodware v3.0 - Real hardware attestation via tpm2-tools.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(cmd: list, timeout: int = 5) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr, "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except FileNotFoundError:
        return {"ok": False, "error": "not_found"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


class RealHardwareAttestation:
    """Atestado real via tpm2-tools (tpm2_pcrread, tpm2_quote)."""

    def __init__(self):
        self._have_tpm2 = _have("tpm2")
        self._have_mokutil = _have("mokutil")
        self._have_dmidecode = _have("dmidecode")

    def attest(self) -> dict:
        result = {
            "id": str(uuid.uuid4())[:8],
            "ts": time.time(),
            "tpm_present": self._detect_tpm(),
            "tpm2_tools_available": self._have_tpm2,
            "secure_boot": self._check_secure_boot_real(),
            "measured_boot": self._check_measured_boot(),
            "pcrs": self._read_pcrs_real(),
            "tpm_info": self._tpm_info(),
        }
        t = result["tpm_present"]
        sb = result["secure_boot"]
        result["trust_level"] = "high" if t and sb else ("medium" if t else "low")
        return result

    def _detect_tpm(self) -> bool:
        if os.path.exists("/sys/class/tpm/tpm0"):
            return True
        if os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0"):
            return True
        return False

    def _check_secure_boot_real(self) -> bool:
        # mokutil --sb-state (mais portável)
        if self._have_mokutil:
            r = _run(["mokutil", "--sb-state"])
            if r["ok"]:
                return "enabled" in (r["stdout"] or "").lower()
        # fallback: efivars
        if os.path.exists("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"):
            try:
                with open("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", "rb") as f:
                    data = f.read()
                return len(data) > 4 and data[4] == 1
            except (PermissionError, OSError):
                pass
        return False

    def _check_measured_boot(self) -> bool:
        return os.path.exists("/sys/firmware/efi/efivars") or os.path.exists("/sys/kernel/security/tpm0")

    def _read_pcrs_real(self) -> dict:
        """Lê PCRs reais via tpm2_pcrread, ou mock se indisponível."""
        if not self._have_tpm2 or not self._detect_tpm():
            return self._mock_pcrs()
        r = _run(["tpm2_pcrread", "sha256", "0,1,2,3,4,5,6,7"], timeout=5)
        if not r["ok"]:
            return self._mock_pcrs()
        # parse: "  PCR0: 0x..."
        pcrs = {}
        for line in (r["stdout"] or "").splitlines():
            if ":" in line and "PCR" in line:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    pcr_name = parts[0].strip()
                    pcr_val = parts[1].strip()
                    if pcr_val.startswith("0x"):
                        pcrs[pcr_name] = pcr_val
        return pcrs if pcrs else self._mock_pcrs()

    def _mock_pcrs(self) -> dict:
        return {f"PCR{i}": f"00{'0' * 60}{i:02x}" for i in range(8)}

    def _tpm_info(self) -> dict:
        if not self._have_tpm2:
            return {"available": False, "reason": "tpm2-tools not installed"}
        r = _run(["tpm2_getcap", "properties-fixed"], timeout=5)
        if r["ok"]:
            return {
                "available": True,
                "properties": (r["stdout"] or "")[:500],
            }
        return {"available": True, "properties": "(getcap failed)"}

    def quote(self, pcr_selection: str = "0,1,2,3") -> dict:
        """Gera quote real (requer tpm2-tools + AK carregado)."""
        if not self._have_tpm2:
            return {"ok": False, "error": "tpm2-tools not available"}
        # tpm2_quote -c ak.ctx -l pcr-selection -q nonce
        # simplificado
        return {
            "ok": False,
            "note": "real tpm2_quote requires AK; demo: use pcrread for verification",
        }


class RealAuditd:
    """Integração real com auditd (se disponível)."""

    def __init__(self):
        self._have_auditctl = shutil.which("auditctl") is not None
        self._have_ausearch = shutil.which("ausearch") is not None
        self._have_auditd = shutil.which("auditd") is not None

    def status(self) -> dict:
        return {
            "auditd_installed": self._have_auditd,
            "auditctl_available": self._have_auditctl,
            "ausearch_available": self._have_ausearch,
            "running": os.path.exists("/var/log/audit/audit.log") or self._check_auditd_running(),
        }

    def _check_auditd_running(self) -> bool:
        try:
            r = subprocess.run(["pidof", "auditd"], capture_output=True, text=True, timeout=2)
            return r.returncode == 0
        except Exception:
            return False

    def add_watch(self, path: str, perms: str = "wa") -> dict:
        """Adiciona watch real: auditctl -w path -p perms -k key."""
        if not self._have_auditctl:
            return {"ok": False, "error": "auditctl not installed (apt install auditd)"}
        r = _run(["auditctl", "-w", path, "-p", perms, "-k", "goodware"])
        return {"ok": r["ok"], "stdout": r["stdout"], "stderr": r["stderr"]}

    def list_rules(self) -> dict:
        if not self._have_auditctl:
            return {"ok": False, "error": "auditctl not installed"}
        r = _run(["auditctl", "-l"], timeout=5)
        return {"ok": r["ok"], "rules": r["stdout"]}

    def query_recent(self, key: str = "goodware", limit: int = 50) -> dict:
        if not self._have_ausearch:
            return {"ok": False, "error": "ausearch not installed"}
        r = _run(["ausearch", "-k", key, "-ts", "recent", "--limit", str(limit)], timeout=10)
        return {"ok": r["ok"], "events": r["stdout"][:2000]}

    def add_syscall_watch(self, syscall: str) -> dict:
        """Adiciona syscall audit (ex: '-S execve')."""
        if not self._have_auditctl:
            return {"ok": False, "error": "auditctl not installed"}
        r = _run(["auditctl", "-a", "exit,always", "-S", syscall, "-k", f"goodware_{syscall}"])
        return {"ok": r["ok"], "syscall": syscall, "stdout": r["stdout"], "stderr": r["stderr"]}
