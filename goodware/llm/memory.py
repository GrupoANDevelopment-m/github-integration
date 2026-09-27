"""
Goodware v3.0 — Persistent Memory.

Sistema de memória persistente para o LLM Brain.
- Curto prazo: últimos eventos
- Longo prazo: learnings, preferences, factos confirmados
- Pesquisa por keywords / tags
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.llm.memory")


MEMORY_DIR = Path("/workspace/goodware-v3/data/memory")


class MemoryEntry:
    """Entrada de memória."""

    def __init__(self, key: str, value: Any, tags: List[str] = None,
                 expires_at: float = None):
        self.key = key
        self.value = value
        self.tags = tags or []
        self.created_at = time.time()
        self.expires_at = expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "tags": self.tags,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MemoryEntry":
        e = cls(d["key"], d["value"], d.get("tags", []), d.get("expires_at"))
        e.created_at = d.get("created_at", time.time())
        return e

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class PersistentMemory:
    """Memória persistente com busca."""

    def __init__(self):
        MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        self._path = MEMORY_DIR / "memory.json"
        self._entries: Dict[str, MemoryEntry] = {}
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                for d in data.get("entries", []):
                    e = MemoryEntry.from_dict(d)
                    if not e.is_expired():
                        self._entries[e.key] = e
            except Exception as e:
                log.warning(f"Failed to load memory: {e}")

    def _save(self) -> None:
        try:
            data = {"entries": [e.to_dict() for e in self._entries.values()]}
            self._path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        except Exception as e:
            log.warning(f"Failed to save memory: {e}")

    def store(self, key: str, value: Any, tags: List[str] = None,
              expires_in: float = None) -> None:
        """Guarda valor."""
        expires_at = None
        if expires_in:
            expires_at = time.time() + expires_in
        with self._lock:
            self._entries[key] = MemoryEntry(key, value, tags, expires_at)
            self._save()

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            entry = self._entries.get(key)
            if entry and not entry.is_expired():
                return entry.value
        return default

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._entries:
                del self._entries[key]
                self._save()
                return True
        return False

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Procura por substring em key, value, ou tags."""
        q = query.lower()
        results = []
        with self._lock:
            for entry in self._entries.values():
                if entry.is_expired():
                    continue
                hay = " ".join([
                    entry.key.lower(),
                    str(entry.value).lower(),
                    " ".join(t.lower() for t in entry.tags),
                ])
                if q in hay:
                    results.append(entry.to_dict())
        return results[:limit]

    def by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """Lista entries com tag específica."""
        with self._lock:
            return [
                e.to_dict() for e in self._entries.values()
                if not e.is_expired() and tag in e.tags
            ]

    def list_keys(self) -> List[str]:
        with self._lock:
            return [k for k, e in self._entries.items() if not e.is_expired()]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._save()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_entries": len(self._entries),
                "keys": self.list_keys(),
                "size_bytes": self._path.stat().st_size if self._path.exists() else 0,
            }


_memory: Optional[PersistentMemory] = None


def get_memory() -> PersistentMemory:
    global _memory
    if _memory is None:
        _memory = PersistentMemory()
    return _memory
