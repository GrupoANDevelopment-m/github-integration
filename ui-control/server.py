#!/usr/bin/env python3
"""Static server for the Goodware Console.

Serves the UI on :8445 and proxies /api/* to Goodware backend on :8444.
"""
import os
import sys
import http.server
import socketserver
from pathlib import Path
import urllib.request
import json

ROOT = Path(__file__).parent
PORT = int(os.environ.get("GOODWARE_UI_PORT", "8445"))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Session-Token")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/api/"):
            self.proxy_request()
        elif self.path == "/" or self.path == "":
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self.proxy_request()
        else:
            self.send_response(405)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def proxy_request(self):
        try:
            target = "http://127.0.0.1:8444" + self.path
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else None
            req = urllib.request.Request(target, data=body, method="POST" if body else "GET")
            for k, v in self.headers.items():
                if k.lower() not in ("host", "content-length"):
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e), "hint": "Goodware backend on :8444"}.encode()))

    def log_message(self, fmt, *args):
        pass  # Silenciar


if __name__ == "__main__":
    print(f"╔══════════════════════════════════════════════════════════╗")
    print(f"║  GOODWARE v3.0 — Console de Comando                     ║")
    print(f"║  UI:    http://localhost:{PORT}/                          ║")
    print(f"║  Proxy: /api/* → localhost:8444 (Goodware backend)      ║")
    print(f"╚══════════════════════════════════════════════════════════╝")
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()