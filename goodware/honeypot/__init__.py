"""Goodware v3.0 — Honeypot integration layer.

Real honeypot integrations:
  - Cowrie (SSH/Telnet honeypot) — https://github.com/cowrie/cowrie
  - Legacy HTTP/SSH honeypots (kept for backwards compatibility)

All production deployments should use Cowrie.
"""
from .legacy import (
    HoneypotLog,
    HttpHoneypot,
    SshHoneypot,
    HoneypotManager,
)
from .cowrie_integration import CowrieIntegration

__all__ = [
    "HoneypotLog",
    "HttpHoneypot",
    "SshHoneypot",
    "HoneypotManager",
    "CowrieIntegration",
]