"""
Goodware v3.0 - Real hardware attestation via tpm2-tools (or soft TPM).

Suporta:
1. TPM físico real (/dev/tpm0 + tpm2-tools)
2. swtpm (TPM software via socket TCP/Unix)
3. Soft TPM interno (implementação TCG spec com PQC)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import uuid

log = logging.getLogger("goodware.physical.attestation")


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
    """Atestado real via tpm2-tools, swtpm, ou soft TPM (PQC-backed)."""

    def __init__(self):
        self._have_tpm2 = _have("tpm2")
        self._have_mokutil = _have("mokutil")
        self._have_dmidecode = _have("dmidecode")
        self._tpm_kind = self._detect_tpm_kind()
        self._soft_tpm = None
        if self._tpm_kind == "soft":
            try:
                from goodware.physical.soft_tpm import get_soft_tpm
                self._soft_tpm = get_soft_tpm()
                log.info("Using soft TPM (PQC-backed)")
            except Exception as e:
                log.warning(f"Failed to init soft TPM: {e}")

    def _detect_tpm_kind(self) -> str:
        """Detecta tipo de TPM disponível."""
        if os.path.exists("/sys/class/tpm/tpm0") or os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0"):
            return "physical"
        # Check if swtpm is running
        try:
            r = subprocess.run(["pgrep", "-f", "swtpm"], capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                return "swtpm"
        except Exception:
            pass
        return "soft"

    def attest(self) -> dict:
        """Gera attestation completa."""
        result = {
            "id": str(uuid.uuid4())[:8],
            "ts": time.time(),
            "tpm_kind": self._tpm_kind,
            "tpm_present": self._tpm_kind != "soft",
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

    def _check_secure_boot_real(self) -> bool:
        if self._have_mokutil:
            r = _run(["mokutil", "--sb-state"])
            if r["ok"]:
                return "enabled" in (r["stdout"] or "").lower()
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
        """Lê PCRs reais via tpm2, swtpm, ou soft TPM."""
        # 1. Soft TPM (PQC-backed, sempre disponível)
        if self._soft_tpm:
            return {f"PCR{i}": "0x" + self._soft_tpm.pcr_read(i).hex()
                    for i in range(min(8, self._soft_tpm.PCR_COUNT))}

        # 2. swtpm via socket TCP
        if self._tpm_kind == "swtpm" or os.path.exists("/tmp/swtpm_state"):
            env = os.environ.copy()
            env["TPM2TOOLS_TCTI"] = "swtpm:host=127.0.0.1,port=2321"
            try:
                r = subprocess.run(
                    ["tpm2_pcrread", "sha256", "0,1,2,3,4,5,6,7"],
                    capture_output=True, text=True, timeout=5, env=env
                )
                if r.returncode == 0:
                    pcrs = {}
                    for line in r.stdout.splitlines():
                        if ":" in line and "PCR" in line:
                            parts = line.strip().split(":")
                            if len(parts) >= 2:
                                pcrs[parts[0].strip()] = parts[1].strip()
                    if pcrs:
                        return pcrs
            except Exception:
                pass

        # 3. tpm2-tools directo
        if self._have_tpm2 and self._tpm_kind == "physical":
            r = _run(["tpm2_pcrread", "sha256", "0,1,2,3,4,5,6,7"], timeout=5)
            if r["ok"]:
                pcrs = {}
                for line in (r["stdout"] or "").splitlines():
                    if ":" in line and "PCR" in line:
                        parts = line.strip().split(":")
                        if len(parts) >= 2:
                            pcrs[parts[0].strip()] = parts[1].strip()
                if pcrs:
                    return pcrs

        # Fallback: zeros reais (PCR não-inicializado)
        return {f"PCR{i}": "0x" + "00" * 32 for i in range(8)}

    def _tpm_info(self) -> dict:
        if self._soft_tpm:
            return self._soft_tpm.status()
        if not self._have_tpm2:
            return {"available": False, "reason": "tpm2-tools not installed"}
        r = _run(["tpm2_getcap", "properties-fixed"], timeout=5)
        if r["ok"]:
            return {
                "available": True,
                "kind": self._tpm_kind,
                "properties": (r["stdout"] or "")[:500],
            }
        return {"available": True, "kind": self._tpm_kind, "properties": "(getcap failed)"}

    def quote(self, pcr_selection: str = "0,1,2,3", nonce: Optional[bytes] = None) -> dict:
        """Gera quote de attestation.

        Em prod real:
            tpm2_quote -c ak.ctx -l pcr_selection -q nonce

        Aqui: usa soft TPM com PQC (ML-DSA-44) se disponível,
        senão tpm2_quote real.
        """
        if nonce is None:
            nonce = os.urandom(32)

        # Soft TPM com PQC quote
        if self._soft_tpm:
            pcrs = [int(p) for p in pcr_selection.split(",") if p.strip().isdigit()]
            return {"ok": True, "quote": self._soft_tpm.quote(pcrs, nonce), "source": "soft-tpm-pqc"}

        # tpm2-tools real
        if self._have_tpm2 and self._tpm_kind in ("physical", "swtpm"):
            nonce_hex = nonce.hex()
            # Tentar (sem AK carregado, vai falhar)
            r = _run(["tpm2_quote", "-c", "0x81000001", "-l", f"sha256:{pcr_selection}", "-q", nonce_hex], timeout=5)
            if r["ok"]:
                return {"ok": True, "quote_raw": r["stdout"], "source": "tpm2-tools"}
            return {"ok": False, "error": r.get("stderr", "unknown"), "note": "AK not loaded or tpm2_quote failed"}

        return {"ok": False, "error": "no TPM available"}


class RealAuditd:
    """Integração real com auditd ou fallback para inotify.

    Se auditd não está disponível (sandbox kernel), usa inotify
    via Python para watch filesystem (substitute funcional).
    """

    def __init__(self):
        self._have_auditctl = shutil.which("auditctl") is not None
        self._have_ausearch = shutil.which("ausearch") is not None
        self._have_auditd = shutil.which("auditd") is not None
        self._watches = []  # Fallback inotify

    def status(self) -> dict:
        return {
            "auditd_installed": self._have_auditd,
            "auditctl_available": self._have_auditctl,
            "ausearch_available": self._have_ausearch,
            "running": self._check_auditd_running(),
            "inotify_fallback": not self._have_auditctl,
            "active_watches": len(self._watches),
        }

    def _check_auditd_running(self) -> bool:
        try:
            r = subprocess.run(["pidof", "auditd"], capture_output=True, text=True, timeout=2)
            return r.returncode == 0
        except Exception:
            return False

    def add_watch(self, path: str, perms: str = "wa") -> dict:
        """Adiciona watch real (auditd) ou fallback (inotify)."""
        if self._have_auditctl:
            r = _run(["auditctl", "-w", path, "-p", perms, "-k", "goodware"])
            if r["ok"]:
                return {"ok": True, "method": "auditd", "stdout": r["stdout"]}
        # Fallback inotify
        return self._add_inotify_watch(path, perms)

    def _add_inotify_watch(self, path: str, perms: str) -> dict:
        try:
            import inotify_simple
            inot = inotify_simple.INotify()
            mask = 0
            if "r" in perms: mask |= inotify_simple.flags.MODIFY
            if "w" in perms: mask |= inotify_simple.flags.WRITE
            if "a" in perms: mask |= inotify_simple.flags.ACCESS
            if "x" in perms: mask |= inotify_simple.flags.EXEC_MODIFY
            wd = inot.add_watch(path, mask)
            self._watches.append({"path": path, "wd": wd, "inot": inot, "mask": mask})
            return {"ok": True, "method": "inotify", "watch_descriptor": wd}
        except ImportError:
            pass

        # Pure-python fallback via os.stat polling
        watch = {"path": path, "perms": perms, "method": "stat-polling", "events": []}
        if os.path.exists(path):
            watch["mtime"] = os.path.getmtime(path)
            watch["size"] = os.path.getsize(path)
        self._watches.append(watch)
        return {"ok": True, "method": "stat-polling", "watch": watch}

    def list_rules(self) -> dict:
        if self._have_auditctl:
            r = _run(["auditctl", "-l"], timeout=5)
            return {"ok": r["ok"], "rules": r["stdout"], "method": "auditd"}
        return {"ok": True, "rules": [w["path"] for w in self._watches], "method": "fallback"}

    def query_recent(self, key: str = "goodware", limit: int = 50) -> dict:
        if self._have_ausearch:
            r = _run(["ausearch", "-k", key, "-ts", "recent", "--limit", str(limit)], timeout=10)
            return {"ok": r["ok"], "events": r["stdout"][:2000], "method": "auditd"}

        # Fallback: ler ficheiros watched
        events = []
        for w in self._watches:
            p = w.get("path")
            if not p or not os.path.exists(p):
                continue
            try:
                st = os.stat(p)
                mtime = st.st_mtime
                size = st.st_size
                if w.get("method") == "stat-polling":
                    if w.get("mtime") != mtime or w.get("size") != size:
                        events.append({
                            "path": p,
                            "mtime": mtime,
                            "size": size,
                            "type": "modify",
                        })
                        w["mtime"] = mtime
                        w["size"] = size
                        w["events"].append(events[-1])
            except Exception:
                pass
        return {"ok": True, "events": events, "method": "fallback", "watched": len(self._watches)}

    def add_syscall_watch(self, syscall: str) -> dict:
        if self._have_auditctl:
            r = _run(["auditctl", "-a", "exit,always", "-S", syscall, "-k", f"goodware_{syscall}"])
            return {"ok": r["ok"], "syscall": syscall, "stdout": r["stdout"], "stderr": r["stderr"], "method": "auditd"}
        return {"ok": False, "error": "auditctl not installed; syscall watching unavailable in fallback mode"}


class RealFirewall:
    """Real nftables/iptables integration."""

    def __init__(self):
        self._have_nft = shutil.which("nft") is not None
        self._have_iptables = shutil.which("iptables") is not None

    def status(self) -> dict:
        """Estado do firewall."""
        if self._have_nft:
            r = _run(["nft", "list", "ruleset"], timeout=5)
            return {
                "backend": "nftables",
                "available": r["ok"],
                "ruleset_lines": len((r.get("stdout") or "").splitlines()) if r["ok"] else 0,
                "ruleset_preview": (r.get("stdout") or "")[:500],
            }
        elif self._have_iptables:
            r = _run(["iptables", "-L", "-n"], timeout=5)
            return {
                "backend": "iptables",
                "available": r["ok"],
                "rules_preview": (r.get("stdout") or "")[:500],
            }
        return {"backend": "none", "available": False}

    def block_ip(self, ip: str, table: str = "filter", chain: str = "INPUT") -> dict:
        """Block real via nftables."""
        if not self._have_nft:
            return {"ok": False, "error": "nft not available", "ip": ip}
        # Verifica se tabela existe
        _run(["nft", "create", "table", "inet", "goodware"], timeout=2)
        _run(["nft", "create", "chain", "inet", "goodware", chain,
              "{ type filter hook input priority 0 ; }"], timeout=2)

        # Adiciona regra
        r = _run(["nft", "add", "rule", "inet", "goodware", chain,
                  "ip", "saddr", ip, "drop"], timeout=2)
        return {"ok": r["ok"], "ip": ip, "table": "goodware", "chain": chain,
                "stderr": r.get("stderr", ""), "stdout": r.get("stdout", "")}

    def list_rules(self) -> dict:
        if not self._have_nft:
            return {"ok": False, "error": "nft not available"}
        r = _run(["nft", "list", "ruleset"], timeout=5)
        return {"ok": r["ok"], "ruleset": r.get("stdout", "")}


class RealClamAV:
    """Integração real com ClamAV."""

    def __init__(self):
        self._have_clamscan = shutil.which("clamscan") is not None
        self._have_freshclam = shutil.which("freshclam") is not None

    def status(self) -> dict:
        info = {
            "clamscan_available": self._have_clamscan,
            "freshclam_available": self._have_freshclam,
        }
        if self._have_clamscan:
            r = _run(["clamscan", "--version"], timeout=3)
            info["version"] = (r.get("stdout") or "").strip()
            # Check signature count
            sig_path = "/var/lib/clamav/main.cvd"
            if os.path.exists(sig_path):
                info["signatures_main"] = os.path.getsize(sig_path)
            sig_path = "/var/lib/clamav/daily.cvd"
            if os.path.exists(sig_path):
                info["signatures_daily"] = os.path.getsize(sig_path)
        return info

    def scan(self, path: str) -> dict:
        """Scan real com clamscan."""
        if not self._have_clamscan:
            return {"ok": False, "error": "clamscan not installed"}
        r = _run(["clamscan", "-r", "--no-summary", path], timeout=60)
        # clamscan exit codes:
        # 0 = no virus found
        # 1 = virus found
        return {
            "ok": True,
            "infected": r["code"] == 1,
            "scan_output": (r.get("stdout") or "")[:2000],
        }

    def update(self) -> dict:
        """Update signatures (freshclam)."""
        if not self._have_freshclam:
            return {"ok": False, "error": "freshclam not installed"}
        r = _run(["freshclam", "--quiet"], timeout=120)
        return {
            "ok": r["ok"],
            "output": (r.get("stdout") or "")[:500],
            "stderr": (r.get("stderr") or "")[:500],
        }
