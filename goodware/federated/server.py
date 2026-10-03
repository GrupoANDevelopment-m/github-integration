"""In-process federated learning server.

Production version:
- Secret loaded from env / config file (NEVER hardcoded).
- If no valid secret configured, server refuses to start (returns clear error).
- Listen address configurable (default 127.0.0.1:8443 — bind localhost only).
- For multi-node deployment, set federated.host=0.0.0.0 with TLS.
- Honest reporting: ready=True iff secret configured and not placeholder.
"""
from __future__ import annotations
import json
import logging
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("goodware.federated.server")


class _Handler(BaseHTTPRequestHandler):
    fed_server = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self._json({"ok": True, "version": "1.0", "ready": self.fed_server.is_ready()})
        elif self.path == "/model":
            model = self.fed_server.current_model()
            self._json(model)
        elif self.path == "/stats":
            self._json(self.fed_server.stats())
        elif self.path == "/status":
            self._json(self.fed_server.status())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/push":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            sig = self.headers.get("X-Signature", "")
            if not self.fed_server.is_ready():
                self._json({"error": "server not ready: no secret configured"}, 503)
                return
            if not self.fed_server.verify_signature(body, sig):
                self._json({"error": "bad signature"}, 401)
                return
            try:
                data = json.loads(body)
            except Exception as e:
                self._json({"error": f"invalid json: {e}"}, 400)
                return
            result = self.fed_server.handle_push(data)
            self._json(result)
        else:
            self._json({"error": "not found"}, 404)

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FederatedServer:
    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8443

    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.secret = self._load_secret()
        self.host = config.get("federated.host", self.DEFAULT_HOST)
        self.port = int(config.get("federated.port", self.DEFAULT_PORT))
        self._global_model = {"version": 0, "model": None, "n": 0}
        self._history = []
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer = None
        self._thread: threading.Thread = None
        self._running = False
        # Statistics
        self._total_pushes = 0
        self._rejected_pushes = 0
        self._unique_nodes = set()

    def attach(self, engine):
        pass

    def _load_secret(self) -> str:
        """Load secret from env / config file. Reject hardcoded default."""
        env_secret = os.environ.get("GOODWARE_FEDERATED_SECRET")
        if env_secret:
            log.info("Server: loaded secret from env var GOODWARE_FEDERATED_SECRET")
            return env_secret
        config_secret = self.config.get("federated.node_secret")
        if config_secret and config_secret != "change-me-in-production":
            log.info("Server: loaded secret from config (federated.node_secret)")
            return config_secret
        secret_path = self.config.get("federated.secret_file", "/etc/goodware/federated.secret")
        if os.path.exists(secret_path):
            try:
                with open(secret_path) as f:
                    s = f.read().strip()
                if s and s != "change-me-in-production":
                    log.info("Server: loaded secret from %s", secret_path)
                    return s
            except Exception as e:
                log.warning("Server: failed to read %s: %s", secret_path, e)
        log.error(
            "Server: NO federated secret configured. Set GOODWARE_FEDERATED_SECRET "
            "or federated.secret_file. Server will REFUSE to accept pushes."
        )
        return ""

    def is_ready(self) -> bool:
        """Ready iff secret is configured and not the placeholder."""
        return bool(self.secret) and self.secret != "change-me-in-production"

    def verify_signature(self, body: bytes, sig: str) -> bool:
        import hashlib, hmac
        expected = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)

    def handle_push(self, payload: dict) -> dict:
        from .aggregation import SecureAggregator
        updates = payload.get("updates", [])
        node_id = payload.get("node_id", "?")
        # Anti-spam: cap number of updates per push
        if len(updates) > 1000:
            self._rejected_pushes += 1
            return {"ok": False, "error": "too many updates in single push (max 1000)"}
        with self._lock:
            try:
                agg = SecureAggregator.aggregate(updates)
            except Exception as e:
                self._rejected_pushes += 1
                return {"ok": False, "error": f"aggregation failed: {e}"}
            if agg.get("model") is not None:
                self._global_model = agg
            self._history.append({
                "ts": time.time(),
                "node": node_id,
                "n": len(updates),
            })
            self._history = self._history[-100:]
            self._unique_nodes.add(node_id)
            self._total_pushes += 1
        try:
            from goodware.core.events import EventType
            self.engine.emit(
                EventType.FED_MODEL_RECEIVED,
                {"n": len(updates), "version": self._global_model["version"], "node": node_id},
                source="federated-server"
            )
        except Exception:
            pass
        return {"ok": True, "version": self._global_model["version"]}

    def current_model(self):
        with self._lock:
            return dict(self._global_model)

    def stats(self):
        with self._lock:
            return {
                "history": len(self._history),
                "current_version": self._global_model["version"],
                "unique_nodes": len(self._unique_nodes),
                "total_pushes": self._total_pushes,
                "rejected_pushes": self._rejected_pushes,
            }

    def start(self):
        if self._running:
            return
        if not self.is_ready():
            log.error(
                "FederatedServer.start(): NO SECRET CONFIGURED. Server will NOT start. "
                "Set GOODWARE_FEDERATED_SECRET env var or federated.secret_file."
            )
            return
        self._running = True
        try:
            _Handler.fed_server = self
            self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="fed-server")
            self._thread.start()
            log.info(f"Federated server listening on {self.host}:{self.port}")
        except OSError as e:
            log.error(f"Federated server bind failed on {self.host}:{self.port}: {e}")
            self._running = False

    def stop(self):
        self._running = False
        try:
            if self._httpd:
                self._httpd.shutdown()
        except Exception:
            pass

    def status(self):
        return {
            "running": self._running,
            "ready": self.is_ready(),
            "host": self.host,
            "port": self.port,
            "model_version": self._global_model["version"],
            "unique_nodes": len(self._unique_nodes),
            "total_pushes": self._total_pushes,
            "rejected_pushes": self._rejected_pushes,
            "secret_source": "env" if os.environ.get("GOODWARE_FEDERATED_SECRET")
                             else "config" if self.config.get("federated.node_secret", "") != "change-me-in-production"
                             else "none",
        }