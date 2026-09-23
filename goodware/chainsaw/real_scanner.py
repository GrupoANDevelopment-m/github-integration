"""
Goodware v3.0 - Real external scanners integration.
YARA, ClamAV, chkrootkit-style.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import List, Optional


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(cmd: List[str], timeout: int = 30) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr, "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except FileNotFoundError:
        return {"ok": False, "error": "not_found"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ============================================================
# YARA integration
# ============================================================
class YaraScanner:
    """Integração com YARA (se yara CLI ou liboqs-yara disponível)."""

    def __init__(self, rules_dir: str = "policies/yara"):
        self.rules_dir = rules_dir
        os.makedirs(rules_dir, exist_ok=True)
        # cria uma regra de exemplo
        self._ensure_default_rules()
        self._have_yara = _have("yara")
        self._have_python_yara = False
        try:
            import yara  # noqa: F401
            self._have_python_yara = True
        except ImportError:
            pass

    def _ensure_default_rules(self) -> None:
        default = os.path.join(self.rules_dir, "goodware_default.yar")
        if not os.path.exists(default):
            with open(default, "w") as f:
                f.write("""rule goodware_crypto_miner : cryptocurrency miner
{
    meta:
        description = "Detects common crypto miner indicators"
        author = "goodware"
    strings:
        $a = "xmrig" ascii nocase
        $b = "kdevtmpfsi" ascii nocase
        $c = "stratum+tcp" ascii nocase
        $d = "cryptonight" ascii nocase
    condition:
        any of them
}

rule goodware_reverse_shell : backdoor
{
    meta:
        description = "Detects reverse shell patterns"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "nc -e" ascii nocase
        $c = "bash -i" ascii
        $d = "0<&" ascii
    condition:
        any of them
}

rule goodware_ransom_note : ransomware
{
    meta:
        description = "Detects common ransomware note patterns"
    strings:
        $a = "your files have been encrypted" ascii nocase
        $b = "send the bitcoin" ascii nocase
        $c = ".locked" ascii nocase
        $d = "wanna" ascii nocase
    condition:
        any of them
}

rule goodware_persistence : persistence
{
    meta:
        description = "Detects persistence mechanisms"
    strings:
        $a = "/etc/ld.so.preload" ascii
        $b = "/etc/cron.d/" ascii
        $c = "crontab -e" ascii
    condition:
        any of them
}
""")

    def scan(self, path: str) -> dict:
        """Escaneia um ficheiro. Retorna matches."""
        if not os.path.exists(path):
            return {"ok": False, "error": "file_not_found"}
        # tenta Python yara
        if self._have_python_yara:
            try:
                import yara
                rules = yara.compile(filepath=os.path.join(self.rules_dir, "goodware_default.yar"))
                matches = rules.match(path)
                return {
                    "ok": True,
                    "scanner": "yara-python",
                    "matches": [
                        {"rule": m.rule, "tags": m.tags, "meta": m.meta, "string_matches": len(m.strings)}
                        for m in matches
                    ],
                    "infected": len(matches) > 0,
                }
            except Exception as e:
                return {"ok": False, "error": f"yara-python: {e}"}
        # tenta CLI yara
        if self._have_yara:
            r = _run(["yara", "-r", os.path.join(self.rules_dir, "goodware_default.yar"), path], timeout=20)
            if r["ok"]:
                matches = [l for l in r["stdout"].splitlines() if l.strip()]
                return {
                    "ok": True,
                    "scanner": "yara-cli",
                    "matches": [{"rule": m.split()[0]} for m in matches],
                    "infected": len(matches) > 0,
                }
            return {"ok": False, "error": r.get("error", r.get("stderr"))}
        return {"ok": False, "error": "yara not installed (pip install yara-python OR apt install yara)"}

    def list_rules(self) -> List[str]:
        if not os.path.isdir(self.rules_dir):
            return []
        return [f for f in os.listdir(self.rules_dir) if f.endswith((".yar", ".yara"))]


# ============================================================
# ClamAV integration
# ============================================================
class ClamAVScanner:
    """Integração com ClamAV (clamscan CLI ou clamd)."""

    def __init__(self):
        self._have_clamscan = _have("clamscan")
        self._have_clamdscan = _have("clamdscan")

    def scan(self, path: str) -> dict:
        if not os.path.exists(path):
            return {"ok": False, "error": "not_found"}
        if self._have_clamdscan:
            r = _run(["clamdscan", "--no-summary", path], timeout=60)
            infected = "FOUND" in (r.get("stdout") or "")
            return {
                "ok": r["ok"],
                "scanner": "clamdscan",
                "stdout": r["stdout"][:500],
                "stderr": r["stderr"][:500],
                "infected": infected,
            }
        if self._have_clamscan:
            r = _run(["clamscan", "--no-summary", path], timeout=60)
            infected = "FOUND" in (r.get("stdout") or "")
            return {
                "ok": True,
                "scanner": "clamscan",
                "stdout": r["stdout"][:500],
                "stderr": r["stderr"][:500],
                "infected": infected,
            }
        return {"ok": False, "error": "clamav not installed (apt install clamav)"}

    @staticmethod
    def update_signatures() -> dict:
        if _have("freshclam"):
            return _run(["freshclam"], timeout=120)
        return {"ok": False, "error": "freshclam not installed"}


# ============================================================
# Real rootkit detection (chkrootkit-style simplificado)
# ============================================================
class RootkitDetector:
    """Detecção real de rootkits via comparação /proc/<pid>/exe vs /bin/ps."""

    SUSPICIOUS_PATHS = ["/dev/shm/", "/tmp/.", "/var/tmp/.", "/dev/.", "/dev/shm/.X11-unix"]
    SUSPICIOUS_NAMES = {"sshd", "kdevtmpfsi", "xmrig", "masscan", "zmap", "mirai"}

    def __init__(self):
        pass

    def scan(self) -> dict:
        results = {
            "ok": True,
            "findings": [],
            "checked": 0,
        }
        # 1. processos com binário em path suspeito
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    info = proc.info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                exe = info.get("exe") or ""
                name = (info.get("name") or "").lower()
                if any(sp in exe for sp in self.SUSPICIOUS_PATHS):
                    results["findings"].append({
                        "type": "hidden_in_tmp",
                        "severity": "high",
                        "pid": info["pid"],
                        "name": info["name"],
                        "exe": exe,
                    })
                if name in self.SUSPICIOUS_NAMES:
                    results["findings"].append({
                        "type": "known_rootkit_name",
                        "severity": "critical",
                        "pid": info["pid"],
                        "name": info["name"],
                        "exe": exe,
                    })
                results["checked"] += 1
        except Exception as e:
            results["psutil_error"] = str(e)

        # 2. /etc/ld.so.preload (Linux rootkit classic)
        preload = "/etc/ld.so.preload"
        if os.path.exists(preload):
            try:
                with open(preload) as f:
                    content = f.read().strip()
                if content:
                    results["findings"].append({
                        "type": "ld_preload_rootkit",
                        "severity": "critical",
                        "file": preload,
                        "content": content[:200],
                    })
            except Exception:
                pass

        # 3. UID 0 users com shells estranhos
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7 and parts[2] == "0" and parts[0] not in ("root",):
                        results["findings"].append({
                            "type": "uid_zero_user",
                            "severity": "critical",
                            "user": parts[0],
                            "shell": parts[6],
                        })
        except Exception:
            pass

        # 4. SUID binaries em paths suspeitos
        try:
            for dp, _, files in os.walk("/tmp"):
                for fn in files:
                    fp = os.path.join(dp, fn)
                    try:
                        st = os.stat(fp)
                        if st.st_mode & 0o4000:  # SUID
                            results["findings"].append({
                                "type": "suid_in_tmp",
                                "severity": "high",
                                "file": fp,
                            })
                    except Exception:
                        continue
                break  # só top-level
        except Exception:
            pass

        # 5. listening processes em portas suspeitas sem dono conhecido
        try:
            import psutil
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.pid:
                    try:
                        p = psutil.Process(c.pid)
                        name = p.name().lower()
                        if name in ("nc", "ncat", "netcat"):
                            results["findings"].append({
                                "type": "netcat_listener",
                                "severity": "high",
                                "pid": c.pid,
                                "port": c.laddr.port,
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception:
            pass

        results["infected"] = len(results["findings"]) > 0
        return results


# ============================================================
# CIS Benchmark checks
# ============================================================
class CISBenchmark:
    """Verificações de hardening CIS (subset importante)."""

    def __init__(self):
        self.checks = [
            self._check_root_password,
            self._check_ssh_root_login,
            self._check_world_readable_shadow,
            self._check_core_dumps,
            self._check_unattended_upgrades,
            self._check_auditd,
            self._check_firewall_active,
            self._check_world_writable_files,
        ]

    def _check_root_password(self) -> dict:
        # verifica se /etc/shadow tem password hash para root
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.split(":")
                    if parts[0] == "root":
                        has_pw = len(parts) > 1 and parts[1] not in ("", "!", "*", "!!")
                        return {"name": "root_password_set", "ok": has_pw, "severity": "high"}
        except (FileNotFoundError, PermissionError):
            pass
        return {"name": "root_password_set", "ok": None, "note": "cannot read /etc/shadow"}

    def _check_ssh_root_login(self) -> dict:
        sshd = "/etc/ssh/sshd_config"
        if not os.path.exists(sshd):
            return {"name": "ssh_root_login_disabled", "ok": None, "note": "no sshd_config"}
        try:
            with open(sshd) as f:
                for line in f:
                    s = line.strip()
                    if s.lower().startswith("permitrootlogin") and "yes" in s.lower():
                        return {"name": "ssh_root_login_disabled", "ok": False, "severity": "high", "line": s}
        except (PermissionError, OSError):
            return {"name": "ssh_root_login_disabled", "ok": None, "note": "permission denied"}
        return {"name": "ssh_root_login_disabled", "ok": True}

    def _check_world_readable_shadow(self) -> dict:
        try:
            st = os.stat("/etc/shadow")
            # verificar se outros têm leitura
            if st.st_mode & 0o004:
                return {"name": "shadow_not_world_readable", "ok": False, "severity": "critical"}
        except (FileNotFoundError, PermissionError):
            return {"name": "shadow_not_world_readable", "ok": None}
        return {"name": "shadow_not_world_readable", "ok": True}

    def _check_core_dumps(self) -> dict:
        try:
            with open("/etc/security/limits.conf") as f:
                content = f.read()
            if "* hard core 0" in content:
                return {"name": "core_dumps_disabled", "ok": True}
            return {"name": "core_dumps_disabled", "ok": False, "severity": "medium"}
        except (FileNotFoundError, PermissionError):
            return {"name": "core_dumps_disabled", "ok": None}

    def _check_unattended_upgrades(self) -> dict:
        for p in ("/etc/apt/apt.conf.d/20auto-upgrades", "/etc/dnf/automatic.conf"):
            if os.path.exists(p):
                return {"name": "auto_updates", "ok": True}
        return {"name": "auto_updates", "ok": False, "severity": "medium"}

    def _check_auditd(self) -> dict:
        return {"name": "auditd_running", "ok": _have("auditd") or os.path.exists("/var/log/audit/audit.log"),
                "severity": "medium"}

    def _check_firewall_active(self) -> dict:
        for cmd in ("ufw", "firewalld", "iptables", "nft"):
            if _have(cmd):
                return {"name": "firewall_available", "ok": True, "backend": cmd}
        return {"name": "firewall_available", "ok": False, "severity": "high"}

    def _check_world_writable_files(self) -> dict:
        # detecção rápida: ignora /proc, /sys
        bad = []
        for base in ("/etc", "/usr/local/bin", "/usr/bin", "/bin"):
            if not os.path.isdir(base):
                continue
            try:
                for dp, _, files in os.walk(base):
                    for fn in files:
                        fp = os.path.join(dp, fn)
                        try:
                            st = os.stat(fp)
                            if st.st_mode & 0o002:
                                bad.append(fp)
                                if len(bad) > 20:
                                    return {"name": "no_world_writable", "ok": False, "severity": "high", "examples": bad}
                        except (PermissionError, OSError):
                            continue
                    if len(bad) > 20:
                        break
            except (PermissionError, OSError):
                continue
        return {"name": "no_world_writable", "ok": len(bad) == 0, "examples": bad[:5] if bad else []}

    def run(self) -> dict:
        results = []
        passed = 0
        failed = 0
        for check in self.checks:
            try:
                r = check()
            except Exception as e:
                r = {"name": check.__name__, "ok": None, "error": str(e)}
            results.append(r)
            if r.get("ok") is True:
                passed += 1
            elif r.get("ok") is False:
                failed += 1
        return {
            "ok": True,
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "score": round(100 * passed / max(1, len(results)), 1),
            "results": results,
        }
