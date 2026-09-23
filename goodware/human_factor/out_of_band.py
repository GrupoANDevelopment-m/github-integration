"""
Goodware v3.0 - Out-of-band verification (log, telegram, email).
"""
from __future__ import annotations
import json
import os
import time
import uuid


class OutOfBandVerifier:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        channel = config.get("human_factor.out_of_band.channel", "log")
        self.channel = channel
        self.queue_path = os.path.join(engine.config.get("general.data_dir", "data"), "oob_queue.json")
        os.makedirs(os.path.dirname(self.queue_path), exist_ok=True)
        self._queue = self._load()

    def _load(self):
        if os.path.exists(self.queue_path):
            try:
                with open(self.queue_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        try:
            with open(self.queue_path, "w") as f:
                json.dump(self._queue, f, indent=2)
        except Exception:
            pass

    def request_verification(self, action, request_id):
        msg_id = str(uuid.uuid4())[:8]
        rec = {
            "msg_id": msg_id,
            "request_id": request_id,
            "action": action,
            "ts": time.time(),
            "status": "pending",
            "channel": self.channel,
        }
        self._queue[msg_id] = rec
        self._save()
        if self.channel == "telegram":
            self._send_telegram(rec)
        elif self.channel == "email":
            self._send_email(rec)
        else:
            self._log(rec)
        return msg_id

    def _log(self, rec):
        log_dir = self.engine.config.get("general.log_dir", "logs")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "oob.log"), "a") as f:
            f.write(f"[OOB] {rec['msg_id']} request={rec['request_id']} action={rec['action']}\n")

    def _send_telegram(self, rec):
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat = os.environ.get("TELEGRAM_CHAT_ID")
        if not (token and chat):
            self._log(rec)
            return
        try:
            import requests
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            text = f"[Goodware] Verify action: {rec['action']} (request {rec['request_id']})"
            requests.post(url, json={"chat_id": chat, "text": text}, timeout=5)
        except Exception as e:
            self.engine.logger.error(f"oob telegram: {e}")
            self._log(rec)

    def _send_email(self, rec):
        try:
            from email.message import EmailMessage
            import smtplib
            host = os.environ.get("SMTP_HOST")
            port = int(os.environ.get("SMTP_PORT", "587"))
            user = os.environ.get("SMTP_USER")
            pw = os.environ.get("SMTP_PASS")
            to = os.environ.get("OOB_TO_EMAIL")
            if not all([host, user, pw, to]):
                self._log(rec)
                return
            msg = EmailMessage()
            msg["Subject"] = f"[Goodware] Verify {rec['request_id']}"
            msg["From"] = user
            msg["To"] = to
            msg.set_content(f"Action: {rec['action']}")
            with smtplib.SMTP(host, port) as s:
                s.starttls()
                s.login(user, pw)
                s.send_message(msg)
        except Exception as e:
            self.engine.logger.error(f"oob email: {e}")
            self._log(rec)

    def poll(self, request_id):
        for r in self._queue.values():
            if r["request_id"] == request_id:
                return r
        return None
