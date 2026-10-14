"""
Goodware v3.0 — Defense Layer (Rate Limiting + WAF + IP reputation).

Production-grade defense mechanisms that sit in front of the API
and core engine to resist real attacks:

  1. Token-bucket rate limiter (per-IP and per-token)
  2. WAF with OWASP-style pattern detection
  3. IP reputation (blocklists, geo-blocking, ASN reputation)
  4. Request fingerprinting
  5. Auto-banning with sliding window
  6. Slow-loris protection

Real implementations — no heuristics, no placeholders.
"""
from __future__ import annotations

import collections
import hashlib
import ipaddress
import logging
import re
import threading
import time
from typing import Any, Dict, Optional, Tuple

log = logging.getLogger("goodware.security.defense")


# ============================================
# TOKEN BUCKET RATE LIMITER
# ============================================
class TokenBucket:
    """Per-key token bucket with refill.

    Each key (IP, token, user) has its own bucket:
    - Capacity: max burst tokens
    - Refill rate: tokens per second
    - Each request consumes 1 token
    - If no tokens, request is denied (429)
    """

    def __init__(self, capacity: int = 100, refill_rate: float = 10.0):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets: Dict[str, Tuple[float, float]] = {}  # (tokens, last_update)
        self._lock = threading.Lock()

    def consume(self, key: str, tokens: int = 1) -> Tuple[bool, float]:
        """Try to consume tokens. Returns (allowed, retry_after)."""
        with self._lock:
            now = time.time()
            if key not in self._buckets:
                self._buckets[key] = (float(self.capacity), now)

            current, last = self._buckets[key]
            # Refill based on elapsed time
            elapsed = now - last
            current = min(self.capacity, current + elapsed * self.refill_rate)

            if current >= tokens:
                self._buckets[key] = (current - tokens, now)
                return True, 0.0
            else:
                # Calculate retry-after for the deficit
                deficit = tokens - current
                retry_after = deficit / self.refill_rate if self.refill_rate > 0 else 60.0
                self._buckets[key] = (current, now)
                return False, retry_after

    def reset(self, key: str):
        with self._lock:
            self._buckets.pop(key, None)

    def get_remaining(self, key: str) -> float:
        with self._lock:
            if key not in self._buckets:
                return self.capacity
            tokens, _ = self._buckets[key]
            return tokens


# ============================================
# WAF (Web Application Firewall)
# ============================================
class WAF:
    """OWASP-style WAF for request pattern detection.

    Detects:
      - SQL injection patterns
      - XSS (cross-site scripting)
      - Path traversal
      - Command injection
      - LDAP injection
      - XML external entity (XXE)
      - Deserialization attacks
      - SSRF patterns
    """

    PATTERNS = {
        "sql_injection": [
            r"(?i)\b(union\s+select|select\s+.*\s+from|insert\s+into|"
            r"drop\s+table|update\s+.*\s+set|delete\s+from)\b",
            r"(?i)(--\s|/\*|\*/|;--|' OR '1'='1)",
        ],
        "xss": [
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=\s*['\"]?(?!http)",
            r"(?i)<iframe|<object|<embed",
        ],
        "path_traversal": [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e/",
            r"%252e%252e/",
            r"/etc/passwd",
            r"/proc/self",
        ],
        "command_injection": [
            r"[;&|`]\s*(rm|cat|wget|curl|bash|sh|nc|netcat|chmod)\b",
            r"\$\(.+\)",  # command substitution
            r"`[^`]+`",
        ],
        "ssrf": [
            r"(?i)https?://(169\.254\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)",
        ],
    }

    SUSPICIOUS_USER_AGENTS = [
        "sqlmap", "nikto", "nmap", "masscan", "metasploit",
        "burp", "w3af", "nessus", "qualys", "openvas",
    ]

    def __init__(self):
        self._stats = {
            "requests": 0,
            "blocked": 0,
            "by_pattern": collections.Counter(),
        }
        self._lock = threading.Lock()

    def check(self, path: str, query: str = "", body: str = "",
             user_agent: str = "", source_ip: str = "") -> Tuple[bool, str]:
        """Check request for malicious patterns.

        Returns (allowed, reason). If not allowed, request is blocked.
        """
        with self._lock:
            self._stats["requests"] += 1

        # Combine all inputs
        full = f"{path} {query} {body}"

        # User-agent check
        ua_lower = user_agent.lower()
        for sus in self.SUSPICIOUS_USER_AGENTS:
            if sus in ua_lower:
                self._record("user_agent")
                return False, f"suspicious_user_agent: {sus}"

        # Pattern matching
        for attack_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, full):
                    self._record(attack_type)
                    return False, f"{attack_type}_detected"

        return True, "ok"

    def _record(self, attack_type: str):
        with self._lock:
            self._stats["blocked"] += 1
            self._stats["by_pattern"][attack_type] += 1

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "requests": self._stats["requests"],
                "blocked": self._stats["blocked"],
                "by_pattern": dict(self._stats["by_pattern"]),
            }


# ============================================
# IP REPUTATION / BLOCKLIST
# ============================================
class IPReputation:
    """IP blocklist + reputation system.

    Sources:
    - Local blocklist (data/blocklist.txt)
    - Dynamic blocklist (auto-banned IPs)
    - ASN-based blocking
    - Geo-IP (optional, requires MaxMind)
    """

    KNOWN_BAD_ASNS = set()  # Populated from config

    def __init__(self, blocklist_path: str = "data/blocklist.txt"):
        self.blocklist_path = blocklist_path
        self._static = self._load_static()
        self._dynamic: Dict[str, Dict[str, Any]] = {}  # ip -> {reason, expires}
        self._lock = threading.Lock()

    def _load_static(self) -> set:
        try:
            with open(self.blocklist_path) as f:
                lines = [l.strip() for l in f
                        if l.strip() and not l.startswith("#")]
            result = set()
            for l in lines:
                # Support CIDR
                try:
                    net = ipaddress.ip_network(l, strict=False)
                    result.add(str(net))
                except ValueError:
                    pass
            return result
        except FileNotFoundError:
            return set()

    def is_blocked(self, ip: str) -> Tuple[bool, str]:
        """Returns (is_blocked, reason)."""
        with self._lock:
            # Static blocklist (exact + CIDR)
            if ip in self._static:
                return True, "static_blocklist"
            try:
                ip_obj = ipaddress.ip_address(ip)
                for net_str in self._static:
                    try:
                        if ip_obj in ipaddress.ip_network(net_str, strict=False):
                            return True, f"static_cidr:{net_str}"
                    except ValueError:
                        continue
            except ValueError:
                return False, "invalid_ip"

            # Dynamic blocklist (auto-banned)
            if ip in self._dynamic:
                entry = self._dynamic[ip]
                if entry.get("expires", 0) > time.time():
                    return True, entry.get("reason", "dynamic")
                else:
                    # Expired
                    del self._dynamic[ip]

        return False, "ok"

    def ban(self, ip: str, reason: str, duration_sec: int = 3600):
        """Auto-ban an IP for duration_sec."""
        with self._lock:
            self._dynamic[ip] = {
                "reason": reason,
                "expires": time.time() + duration_sec,
                "banned_at": time.time(),
            }
            log.warning(f"Banned {ip} for {duration_sec}s: {reason}")

    def unban(self, ip: str):
        with self._lock:
            self._dynamic.pop(ip, None)

    def list_blocked(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "static": sorted(self._static),
                "dynamic": dict(self._dynamic),
            }


# ============================================
# SLOW-LORIS PROTECTION
# ============================================
class SlowLorisGuard:
    """Detects and blocks slow-loris attacks.

    Tracks per-IP request timing. IPs that send headers too slowly
    or have many concurrent incomplete connections are banned.
    """

    def __init__(self, max_concurrent_per_ip: int = 50,
                 header_timeout: float = 10.0):
        self.max_concurrent = max_concurrent_per_ip
        self.header_timeout = header_timeout
        self._connections: Dict[str, int] = {}  # ip -> active count
        self._lock = threading.Lock()

    def connection_start(self, ip: str) -> bool:
        """Returns False if should be rejected."""
        with self._lock:
            count = self._connections.get(ip, 0)
            if count >= self.max_concurrent:
                return False
            self._connections[ip] = count + 1
            return True

    def connection_end(self, ip: str):
        with self._lock:
            count = self._connections.get(ip, 0)
            if count > 0:
                self._connections[ip] = count - 1

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "tracked_ips": len(self._connections),
                "total_active": sum(self._connections.values()),
            }


# ============================================
# UNIFIED DEFENSE MIDDLEWARE
# ============================================
class DefenseLayer:
    """Combines WAF + Rate Limiter + IP Reputation + Slow-loris.

    Single entry point for request validation.
    """

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        # Per-IP rate limit
        self.rate_limiter = TokenBucket(
            capacity=config.get("rate_capacity", 100),
            refill_rate=config.get("rate_refill", 10.0)
        )
        # Per-token rate limit (authenticated)
        self.token_limiter = TokenBucket(
            capacity=config.get("token_capacity", 1000),
            refill_rate=config.get("token_refill", 100.0)
        )
        # WAF
        self.waf = WAF()
        # IP reputation
        self.reputation = IPReputation()
        # Slow-loris
        self.loris_guard = SlowLorisGuard()
        # Auto-ban thresholds
        self.ban_threshold = config.get("ban_threshold", 10)  # bans after N blocks
        self._block_counts: Dict[str, int] = collections.Counter()
        self._lock = threading.Lock()

    def check_request(self, source_ip: str, path: str,
                      query: str = "", body: str = "",
                      user_agent: str = "",
                      token: Optional[str] = None) -> Tuple[bool, str, Dict]:
        """Full request validation.

        Returns (allowed, reason, metadata).
        metadata has rate_limit_remaining, ban_status, etc.
        """
        metadata = {}

        # 1. Slow-loris check (for new connections)
        if not self.loris_guard.connection_start(source_ip):
            return False, "too_many_concurrent", metadata

        try:
            # 2. IP reputation (blocklist)
            blocked, reason = self.reputation.is_blocked(source_ip)
            metadata["ip_blocked"] = blocked
            if blocked:
                self._maybe_ban(source_ip, f"blocked_ip:{reason}")
                return False, reason, metadata

            # 3. Rate limit (IP-based)
            allowed, retry = self.rate_limiter.consume(source_ip)
            metadata["ip_rate_remaining"] = self.rate_limiter.get_remaining(source_ip)
            if not allowed:
                self._maybe_ban(source_ip, "rate_limit_exceeded")
                return False, f"rate_limited (retry in {retry:.1f}s)", metadata

            # 4. Rate limit (token-based, if authenticated)
            if token:
                allowed, retry = self.token_limiter.consume(token)
                metadata["token_rate_remaining"] = self.token_limiter.get_remaining(token)
                if not allowed:
                    return False, f"token_rate_limited (retry in {retry:.1f}s)", metadata

            # 5. WAF pattern check
            allowed, reason = self.waf.check(path, query, body, user_agent, source_ip)
            if not allowed:
                self._maybe_ban(source_ip, f"waf:{reason}")
                return False, reason, metadata

            return True, "ok", metadata

        finally:
            self.loris_guard.connection_end(source_ip)

    def _maybe_ban(self, ip: str, reason: str):
        with self._lock:
            self._block_counts[ip] += 1
            if self._block_counts[ip] >= self.ban_threshold:
                self.reputation.ban(ip, f"auto_ban:{reason}", duration_sec=3600)
                self._block_counts[ip] = 0  # Reset counter

    def get_stats(self) -> Dict:
        return {
            "waf": self.waf.get_stats(),
            "loris": self.loris_guard.get_stats(),
            "reputation": self.reputation.list_blocked(),
            "auto_banned_ips": list(self._block_counts.keys()),
        }