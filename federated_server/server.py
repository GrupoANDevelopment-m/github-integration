#!/usr/bin/env python3
"""Standalone federated server (CLI)."""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# allow imports from parent
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SECRET = os.environ.get("GW_FED_SECRET", "change-me-in-production")
GLOBAL_MODEL = {"version": 0, "model": None, "n": 0}
HISTORY = []
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._json({"ok": True, "version": "1.0"})
        elif self.path == "/model":
            with LOCK:
                self._json(dict(GLOBAL_MODEL))
        elif self.path == "/stats":
            with LOCK:
                self._json({"history": len(HISTORY), "version": GLOBAL_MODEL["version"]})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/push":
            self._json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        sig = self.headers.get("X-Signature", "")
        expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            self._json({"error": "bad signature"}, 401)
            return
        try:
            data = json.loads(body)
        except Exception:
            self._json({"error": "bad json"}, 400)
            return
        updates = data.get("updates", [])
        with LOCK:
            if updates:
                GLOBAL_MODEL["version"] += 1
                GLOBAL_MODEL["n"] = len(updates)
                HISTORY.append({"ts": time.time(), "node": data.get("node_id"), "n": len(updates)})
                HISTORY[:] = HISTORY[-200:]
        self._json({"ok": True, "version": GLOBAL_MODEL["version"]})


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--host", default="127.0.0.1")
    args = p.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"federated server listening on {args.host}:{args.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
