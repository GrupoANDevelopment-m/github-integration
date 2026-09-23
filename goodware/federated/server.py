"""In-process federated learning server."""
from __future__ import annotations
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import numpy as np
from .aggregation import SecureAggregator


class _Handler(BaseHTTPRequestHandler):
    fed_server = None

    def log_message(self, format, *args):
        pass  # silence

    def do_GET(self):
        if self.path == "/healthz":
            self._json({"ok": True, "version": "1.0"})
        elif self.path == "/model":
            model = self.fed_server.current_model()
            self._json(model)
        elif self.path == "/stats":
            self._json(self.fed_server.stats())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/push":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            sig = self.headers.get("X-Signature", "")
            if not self.fed_server.verify_signature(body, sig):
                self._json({"error": "bad signature"}, 401)
                return
            data = json.loads(body)
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
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.secret = config.get("federated.node_secret", "change-me-in-production")
        self.host = "127.0.0.1"
        self.port = 8443
        self._global_model = {"version": 0, "model": None, "n": 0}
        self._history = []
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer = None
        self._thread: threading.Thread = None
        self._running = False

    def attach(self, engine):
        pass

    def verify_signature(self, body: bytes, sig: str) -> bool:
        import hashlib, hmac
        expected = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)

    def handle_push(self, payload: dict) -> dict:
        updates = payload.get("updates", [])
        with self._lock:
            agg = SecureAggregator.aggregate(updates)
            if agg["model"] is not None:
                self._global_model = agg
            self._history.append({"ts": time.time(), "node": payload.get("node_id"), "n": len(updates)})
            self._history = self._history[-100:]
        try:
            from goodware.core.events import EventType
            self.engine.emit(EventType.FED_MODEL_RECEIVED, {"n": len(updates), "version": self._global_model["version"]}, source="federated-server")
        except Exception:
            pass
        return {"ok": True, "version": self._global_model["version"]}

    def current_model(self):
        with self._lock:
            return dict(self._global_model)

    def stats(self):
        with self._lock:
            return {"history": len(self._history), "current_version": self._global_model["version"]}

    def start(self):
        if self._running:
            return
        self._running = True
        try:
            _Handler.fed_server = self
            self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="fed-server")
            self._thread.start()
            self.engine.logger.info(f"federated server listening on {self.host}:{self.port}")
        except OSError as e:
            self.engine.logger.error(f"federated server bind failed: {e}")

    def stop(self):
        self._running = False
        try:
            if self._httpd:
                self._httpd.shutdown()
        except Exception:
            pass

    def status(self):
        return {"running": self._running, "port": self.port, "model_version": self._global_model["version"]}
