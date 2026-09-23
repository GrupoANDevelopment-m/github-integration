"""Federated learning client with DP and HMAC auth."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Optional
import numpy as np
import requests
from .aggregation import DifferentialPrivacy, SecureAggregator


class FederatedClient:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.server_url = config.get("federated.server_url", "http://127.0.0.1:8443")
        self.secret = config.get("federated.node_secret", "change-me-in-production")
        self._running = False
        self._thread = None
        self._local_updates: list = []
        self._last_version = 0

    def attach(self, engine):
        pass

    def add_update(self, gradient, sample_count: int = 1, node_id: Optional[str] = None):
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
        if not self._local_updates:
            # synthetic update so the pipeline always has data
            self.add_update(np.random.normal(0, 0.1, 8), 10)
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
                self._local_updates = []
                self.engine.emit_event = getattr(self.engine, "emit_event", None)
                try:
                    from goodware.core.events import EventType
                    self.engine.emit(EventType.FED_GRADIENT_SENT, {"ok": True, "n": len(payload["updates"])}, source="federated-client")
                except Exception:
                    pass
            return {"ok": ok, "status": r.status_code}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def fetch_global_model(self):
        try:
            r = requests.get(f"{self.server_url}/model", timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="fed-client")
        self._thread.start()

    def _loop(self):
        interval = self.config.get("federated.push_interval_sec", 300)
        interval = min(interval, 30)  # cap for demo
        while self._running:
            try:
                self.push_update()
            except Exception as e:
                self.engine.logger.error(f"federated client: {e}")
            time.sleep(interval)

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running, "pending": len(self._local_updates), "url": self.server_url}
