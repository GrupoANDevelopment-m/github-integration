"""
Goodware v3.0 — Context Manager + Compaction.

Gerencia contexto de conversações longas:
- Trunca contexto quando excede max_tokens
- Resume contexto antigo usando LLM
- Persiste contexto entre sessões
- Cache de prompts repetidos
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.llm.context")


CONTEXT_DIR = Path("/workspace/goodware-v3/data/context")
PROMPT_CACHE_FILE = CONTEXT_DIR / "prompt_cache.json"


class CompactionStrategy:
    """Estratégia para reduzir tamanho do contexto."""

    def __init__(
        self,
        max_tokens: int = 8000,
        keep_recent: int = 4,  # Manter últimas N mensagens
        summarizer: Optional[callable] = None,
    ):
        self.max_tokens = max_tokens
        self.keep_recent = keep_recent
        self._summarizer = summarizer

    def estimate_tokens(self, text: str) -> int:
        return len(text) // 4  # Heurística: ~4 chars por token

    def should_compact(self, messages: List[Dict[str, Any]]) -> bool:
        total = sum(self.estimate_tokens(json.dumps(m)) for m in messages)
        return total > self.max_tokens

    def compact(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compacta mensagens antigas num sumário."""
        if len(messages) <= self.keep_recent:
            return messages

        old = messages[:-self.keep_recent]
        recent = messages[-self.keep_recent:]

        # Sumarizar mensagens antigas
        old_text = "\n".join(f"[{m.get('role','?')}] {m.get('content','')}" for m in old)
        if self._summarizer:
            try:
                summary = self._summarizer(old_text)
            except Exception:
                summary = f"[Sumário automático: {len(old)} mensagens prévias]"
        else:
            summary = f"[Sumário automático de {len(old)} mensagens: {old_text[:500]}...]"

        compact = [{"role": "system", "content": f"Contexto prévio (compactado):\n{summary}"}]
        compact.extend(recent)
        log.info(f"Compacted {len(old)} → 1, kept {len(recent)} recent")
        return compact


class ContextManager:
    """Gerencia contexto e cache."""

    def __init__(self, strategy: Optional[CompactionStrategy] = None):
        CONTEXT_DIR.mkdir(parents=True, exist_ok=True)
        self._strategy = strategy or CompactionStrategy()
        self._prompt_cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._load_cache()

    def _load_cache(self) -> None:
        if PROMPT_CACHE_FILE.exists():
            try:
                self._prompt_cache = json.loads(PROMPT_CACHE_FILE.read_text())
            except Exception:
                self._prompt_cache = {}

    def _save_cache(self) -> None:
        try:
            PROMPT_CACHE_FILE.write_text(json.dumps(self._prompt_cache, indent=2))
        except Exception as e:
            log.warning(f"Failed to save prompt cache: {e}")

    def _hash_prompt(self, prompt: str) -> str:
        return hashlib.sha256(prompt.encode()).hexdigest()[:16]

    def cache_lookup(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Procura resposta em cache."""
        h = self._hash_prompt(prompt)
        with self._lock:
            entry = self._prompt_cache.get(h)
        if entry and (time.time() - entry.get("ts", 0)) < 3600:  # 1h TTL
            return entry.get("response")
        return None

    def cache_store(self, prompt: str, response: Dict[str, Any]) -> None:
        """Guarda resposta em cache."""
        h = self._hash_prompt(prompt)
        with self._lock:
            self._prompt_cache[h] = {"response": response, "ts": time.time()}
            self._save_cache()

    def compact(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self._strategy.compact(messages)

    def save_session(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        """Persiste contexto de uma sessão."""
        path = CONTEXT_DIR / f"{session_id}.json"
        try:
            path.write_text(json.dumps(messages, indent=2, ensure_ascii=False))
        except Exception as e:
            log.warning(f"Failed to save session {session_id}: {e}")

    def load_session(self, session_id: str) -> List[Dict[str, Any]]:
        """Recupera contexto de uma sessão."""
        path = CONTEXT_DIR / f"{session_id}.json"
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                return []
        return []

    def list_sessions(self) -> List[str]:
        return [p.stem for p in CONTEXT_DIR.glob("*.json")]


_manager: Optional[ContextManager] = None


def get_context_manager() -> ContextManager:
    global _manager
    if _manager is None:
        _manager = ContextManager()
    return _manager
