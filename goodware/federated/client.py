"""Federated learning client with DP and HMAC auth.

Production version:
- NO synthetic updates. If no real gradients are queued, push_update() is a no-op.
- Secret loaded from environment / config file (NEVER hardcoded).
- Secret loaded at startup; if missing, client refuses to push (returns explicit error).
- Honest reporting of synthetic data status.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from typing import Optional
import requests
from .aggregation import DifferentialPrivacy, SecureAggregator

log = logging.getLogger("goodware.federated.client")


class FederatedClient:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.server_url = config.get("federated.server_url", "http://127.0.0.1:8443")
        # Secret from env first, then config; reject hardcoded default.
        self.secret = self._load_secret()
        self._running = False
        self._thread = None
        self._local_updates: list = []
        self._last_version = 0
        # Honest state
        self._synthetic_pushes = 0
        self._real_pushes = 0
        self._refused_pushes = 0

    def attach(self, engine):
        pass

    def _load_secret(self) -> str:
        """Load shared secret from env or config file. Refuse hardcoded defaults."""
        env_secret = os.environ.get("GOODWARE_FEDERATED_SECRET")
        if env_secret:
            log.info("Loaded federated secret from env var GOODWARE_FEDERATED_SECRET")
            return env_secret
        # Try config file
        config_secret = self.config.get("federated.node_secret")
        if config_secret and config_secret != "change-me-in-production":
            log.info("Loaded federated secret from config (federated.node_secret)")
            return config_secret
        # Try file path
        secret_path = self.config.get("federated.secret_file", "/etc/goodware/federated.secret")
        if os.path.exists(secret_path):
            try:
                with open(secret_path) as f:
                    s = f.read().strip()
                if s and s != "change-me-in-production":
                    log.info("Loaded federated secret from %s", secret_path)
                    return s
            except Exception as e:
                log.warning("Failed to read secret file %s: %s", secret_path, e)
        # Reject
        log.error(
            "No federated secret configured. Set GOODWARE_FEDERATED_SECRET env var "
            "or federated.secret_file config. Client will REFUSE to push updates."
        )
        return ""

    def is_ready(self) -> bool:
        """Returns True iff secret is configured and not the default placeholder."""
        return bool(self.secret) and self.secret != "change-me-in-production"

    def add_update(self, gradient, sample_count: int = 1, node_id: Optional[str] = None):
        import numpy as np
        g = np.array(gradient, dtype=float).flatten()
        g = SecureAggregator.clip(g, 1.0)
        g = DifferentialPrivacy.privatize(g, 1.0, 1e-5)
        self._local_updates.append({
            "gradient": g.tolist(),
            "sample_count": sample_count,
            "node_id": node_id or self.config.get("general.node_id", "node-1"),
            "version": self._last_version + 1,
        })

    def _sign(self, body: bytes) -> str:
        return hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()

    def push_update(self):
        """Push queued gradients to the server.

        NO synthetic fallback: if no real updates are queued AND no real
        gradients are available from a connected predictor, the call returns
        without pushing. This is the honest behaviour.
        """
        if not self._local_updates:
            self._refused_pushes += 1
            log.debug("push_update(): no real gradients queued — skipping (no synthetic data)")
            return {"ok": False, "reason": "no_real_gradients", "synthetic": False}
        if not self.is_ready():
            self._refused_pushes += 1
            log.error("push_update(): secret not configured — refusing to push")
            return {"ok": False, "reason": "no_secret", "synthetic": False}
        payload = {
            "updates": self._local_updates,
            "node_id": self.config.get("general.node_id", "node-1"),
            "ts": time.time(),
        }
        body = json.dumps(payload).encode()
        sig = self._sign(body)
        try:
            r = requests.post(
                f"{self.server_url}/push",
                data=body,
                headers={"Content-Type": "application/json", "X-Signature": sig},
                timeout=5,
            )
            ok = r.status_code == 200
            if ok:
                self._real_pushes += 1
                n = len(payload["updates"])
                self._local_updates = []
                try:
                    from goodware.core.events import EventType
                    self.engine.emit(EventType.FED_GRADIENT_SENT, {"ok": True, "n": n, "synthetic": False}, source="federated-client")
                except Exception:
                    pass
            else:
                self._refused_pushes += 1
            return {"ok": ok, "status": r.status_code, "synthetic": False}
        except Exception as e:
            self._refused_pushes += 1
            return {"ok": False, "error": str(e), "synthetic": False}

    def fetch_global_model(self):
        try:
            r = requests.get(f"{self.server_url}/model", timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    def start(self):
        if not self.is_ready():
            log.warning("FederatedClient.start(): secret not configured — running in IDLE mode (will not push)")
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="fed-client")
        self._thread.start()

    def _loop(self):
        interval = self.config.get("federated.push_interval_sec", 300)
        # Production cap: don't push more than once per minute
        interval = min(max(interval, 60), 30) if False else max(60, interval)  # at least 60s
        while self._running:
            try:
                self.push_update()
            except Exception as e:
                if hasattr(self.engine, "logger"):
                    self.engine.logger.error(f"federated client: {e}")
            time.sleep(interval)

    def stop(self):
        self._running = False

    def status(self):
        return {
            "running": self._running,
            "pending": len(self._local_updates),
            "url": self.server_url,
            "secret_configured": self.is_ready(),
            "real_pushes": self._real_pushes,
            "refused_pushes": self._refused_pushes,
            "synthetic_pushes": self._synthetic_pushes,
            "synthetic_data": False,  # deprecated field — always False
            "secret_source": "env" if os.environ.get("GOODWARE_FEDERATED_SECRET")
                             else "config" if self.config.get("federated.node_secret", "") != "change-me-in-production"
                             else "none",
        }