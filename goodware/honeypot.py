"""
Goodware v3.0 - Real honeypot.

Sobe serviços falsos (HTTP/SSH/SMB/FTP) que DETECTAM atacantes reais
que estão a fazer scanning ou a tentar aceder. Regista tudo.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from typing import Dict, List, Optional


class HoneypotLog:
    """Log persistente de capturas."""

    def __init__(self, path: str = "data/honeypot_captures.json"):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.captures: List[dict] = self._load()

    def _load(self) -> list:
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save(self) -> None:
        try:
            with open(self.path, "w") as f:
                json.dump(self.captures[-1000:], f, indent=2)  # cap
        except Exception:
            pass

    def record(self, service: str, ip: str, port: int, payload: str = "") -> dict:
        capture = {
            "ts": time.time(),
            "service": service,
            "ip": ip,
            "port": port,
            "payload_preview": payload[:200],
        }
        self.captures.append(capture)
        self._save()
        return capture

    def list_captures(self, limit: int = 100) -> list:
        return self.captures[-limit:]

    def attacker_ips(self) -> List[str]:
        return list({c["ip"] for c in self.captures})


class _TcpService:
    """Base service honeypot — aceita conexão, captura, fecha."""

    def __init__(self, name: str, port: int, banner: bytes, log: HoneypotLog):
        self.name = name
        self.port = port
        self.banner = banner
        self.log = log
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> dict:
        if self._running:
            return {"ok": True, "already_running": True}
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self._sock.listen(5)
            self._sock.settimeout(1.0)
            self._running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True, name=f"honeypot-{self.name}")
            self._thread.start()
            return {"ok": True, "port": self.port}
        except OSError as e:
            return {"ok": False, "error": str(e), "port": self.port}

    def stop(self) -> None:
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
            t.start()

    def _handle(self, conn: socket.socket, addr) -> None:
        ip, port = addr[0], addr[1]
        payload = ""
        try:
            conn.settimeout(3.0)
            # envia banner
            try:
                conn.sendall(self.banner)
            except Exception:
                pass
            # tenta ler input (credenciais, comandos)
            try:
                data = conn.recv(4096)
                if data:
                    try:
                        payload = data.decode("utf-8", errors="ignore")
                    except Exception:
                        payload = repr(data[:200])
            except (socket.timeout, OSError):
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
        # regista
        capture = self.log.record(self.name, ip, port, payload)
        # emite evento no engine
        try:
            from goodware.core.events import EventType, Severity
            from goodware.core.engine import Engine  # noqa
            # não temos referência directa; guardamos só
        except Exception:
            pass


class HttpHoneypot(_TcpService):
    """Honeypot HTTP que devolve 200 OK a tudo (parece servidor web)."""

    def __init__(self, port: int, log: HoneypotLog):
        banner = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>It works!</body></html>\r\n"
        super().__init__("http", port, banner, log)


class FtpHoneypot(_TcpService):
    def __init__(self, port: int, log: HoneypotLog):
        banner = b"220 (vsFTPd 3.0.3)\r\n"
        super().__init__("ftp", port, banner, log)


class SshHoneypot(_TcpService):
    """Honeypot SSH — só captura o banner do cliente."""

    def __init__(self, port: int, log: HoneypotLog):
        banner = b"SSH-2.0-OpenSSH_8.4p1 Debian\r\n"
        super().__init__("ssh", port, banner, log)

    def _handle(self, conn, addr):
        ip, port = addr[0], addr[1]
        payload = ""
        try:
            conn.settimeout(3.0)
            try:
                conn.sendall(self.banner)
            except Exception:
                pass
            try:
                data = conn.recv(4096)
                if data:
                    payload = data.decode("utf-8", errors="ignore")
            except (socket.timeout, OSError):
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
        self.log.record(self.name, ip, port, payload)


class SmbHoneypot(_TcpService):
    """Honeypot SMB — só aceita, regista, fecha."""

    def __init__(self, port: int, log: HoneypotLog):
        # não envia banner — SMB cliente fala primeiro
        super().__init__("smb", port, b"", log)

    def _handle(self, conn, addr):
        ip, port = addr[0], addr[1]
        payload = ""
        try:
            conn.settimeout(3.0)
            try:
                data = conn.recv(4096)
                if data:
                    payload = data[:200].hex()
            except (socket.timeout, OSError):
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
        self.log.record(self.name, ip, port, payload)


class HoneypotManager:
    """Coordena múltiplos honeypots."""

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.log = HoneypotLog()
        self.services: List[_TcpService] = []
        self.enabled = cfg.get("honeypot", {}).get("enabled", True)
        if not self.enabled:
            return
        ports = cfg.get("honeypot", {}).get("ports", {
            "http": 8081,
            "ssh": 2222,
            "ftp": 2121,
            "smb": 4450,  # 445 pode estar ocupado
        })
        if "http" in ports:
            self.services.append(HttpHoneypot(ports["http"], self.log))
        if "ssh" in ports:
            self.services.append(SshHoneypot(ports["ssh"], self.log))
        if "ftp" in ports:
            self.services.append(FtpHoneypot(ports["ftp"], self.log))
        if "smb" in ports:
            self.services.append(SmbHoneypot(ports["smb"], self.log))

    def start_all(self) -> dict:
        results = []
        for s in self.services:
            results.append({"service": s.name, "port": s.port, "result": s.start()})
        return {"started": results, "attacker_ips": self.log.attacker_ips()}

    def stop_all(self) -> None:
        for s in self.services:
            s.stop()

    def status(self) -> dict:
        return {
            "services": [{"name": s.name, "port": s.port, "running": s._running} for s in self.services],
            "captures_count": len(self.log.captures),
            "attacker_ips": self.log.attacker_ips(),
        }

    def captures(self, limit: int = 100) -> list:
        return self.log.list_captures(limit)
