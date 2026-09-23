"""
Goodware v3.0 — Servidor de desenvolvimento do frontend.

Em produção, serve a SPA e proxya para a API Flask.
Em dev, pode ser usado com `python3 -m frontend.dev_server`.

Para usar com o backend Flask real, adicionar rotas estáticas em
goodware.api.server (ver final deste módulo).
"""
from __future__ import annotations
import os
import sys
import json
import secrets
import hashlib
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


# Configuração
FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get('GW_FRONTEND_PORT', '8080'))
API_PORT = int(os.environ.get('GW_API_PORT', '5000'))


# Auth simples — para prod, substituir por JWT/OAuth/SAML
USERS = {
    "admin": hashlib.sha256(b"admin").hexdigest(),
    "operator": hashlib.sha256(b"operator").hexdigest(),
    "viewer": hashlib.sha256(b"viewer").hexdigest(),
}
ROLES = {
    "admin": "admin",
    "operator": "operator",
    "viewer": "viewer",
}
SESSIONS = {}  # token -> {user, expires_at, role}


def _check_password(user, password):
    h = hashlib.sha256(password.encode()).hexdigest()
    return user in USERS and USERS[user] == h


class DevHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # silencioso
        pass

    def _send(self, status, body=b'', content_type='text/plain', extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        return self.rfile.read(length) if length else b''

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, default=str).encode(), 'application/json')

    def _proxy(self, method, path, body=None, query=None):
        """Proxy para a API Flask em :5000"""
        import urllib.request
        url = f"http://127.0.0.1:{API_PORT}{path}"
        if query:
            from urllib.parse import urlencode
            url += "?" + urlencode(query)
        data = body
        if isinstance(data, (dict, list)):
            data = json.dumps(data).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('Content-Type', 'application/json')
        auth = self.headers.get('Authorization')
        if auth:
            req.add_header('Authorization', auth)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                resp = r.read()
                self._send(r.status, resp, r.headers.get('Content-Type', 'application/json'))
        except urllib.error.HTTPError as e:
            self._json(e.code, {"error": e.reason, "detail": e.read().decode('utf-8', errors='replace')})
        except Exception as e:
            self._json(502, {"error": "bad gateway", "detail": str(e)})

    def _serve_static(self, url_path):
        """Serve ficheiros estáticos do frontend."""
        # default → index.html
        if url_path in ('', '/'):
            url_path = '/index.html'
        # segurança: bloquear path traversal
        rel = url_path.lstrip('/')
        full = os.path.normpath(os.path.join(FRONTEND_DIR, rel))
        if not full.startswith(FRONTEND_DIR):
            self._send(403, 'Forbidden')
            return
        if not os.path.exists(full) or not os.path.isfile(full):
            self._send(404, 'Not found')
            return
        ext = os.path.splitext(full)[1].lower()
        ct = {
            '.html': 'text/html; charset=utf-8',
            '.js': 'text/javascript; charset=utf-8',
            '.mjs': 'text/javascript; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.svg': 'image/svg+xml',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.json': 'application/json',
        }.get(ext, 'application/octet-stream')
        with open(full, 'rb') as f:
            self._send(200, f.read(), ct)

    def _check_auth(self):
        """Retorna user/role ou None."""
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return None
        token = auth[7:]
        s = SESSIONS.get(token)
        if not s or s['expires_at'] < time.time():
            return None
        return s

    def do_OPTIONS(self):
        self._send(204)

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path.startswith('/api/'):
            # proxy
            self._proxy('GET', path, query=dict(parse_qs(u.query)))
            return
        if path == '/healthz':
            return self._json(200, {"ok": True})
        if path == '/api/auth/me':
            s = self._check_auth()
            if not s:
                return self._json(401, {"error": "unauthorized"})
            return self._json(200, {"user": s['user'], "role": s['role']})
        # static
        self._serve_static(path)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        if path == '/api/auth/login':
            body = json.loads(self._read_body() or b'{}')
            user = body.get('username', '')
            pwd = body.get('password', '')
            if not _check_password(user, pwd):
                return self._json(401, {"error": "invalid credentials"})
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {
                'user': user,
                'role': ROLES.get(user, 'viewer'),
                'expires_at': time.time() + 3600 * 8,
            }
            return self._json(200, {
                "token": token,
                "user": {"username": user, "role": ROLES.get(user, 'viewer')},
            })
        if path == '/api/auth/logout':
            auth = self.headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                SESSIONS.pop(auth[7:], None)
            return self._json(200, {"ok": True})
        if path.startswith('/api/'):
            self._proxy('POST', path, body=self._read_body())
            return
        self._send(404)

    def do_PUT(self):
        u = urlparse(self.path)
        if u.path.startswith('/api/'):
            self._proxy('PUT', u.path, body=self._read_body())
            return
        self._send(404)

    def do_DELETE(self):
        u = urlparse(self.path)
        if u.path.startswith('/api/'):
            self._proxy('DELETE', u.path)
            return
        self._send(404)


def run():
    print(f"Goodware v3.0 frontend dev server: http://0.0.0.0:{PORT}")
    print(f"  → API proxy: http://127.0.0.1:{API_PORT}")
    print(f"  → Static:    {FRONTEND_DIR}")
    print(f"  → Login:     admin / admin")
    httpd = ThreadingHTTPServer(('0.0.0.0', PORT), DevHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
        httpd.shutdown()


if __name__ == '__main__':
    run()
