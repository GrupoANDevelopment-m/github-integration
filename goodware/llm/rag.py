"""
Goodware v3.0 — RAG (Retrieval-Augmented Generation) simples.

Implementa um mini-vector-store baseado em TF-IDF para
correlacionar queries com knowledge base local.

Knowledge base inclui:
- CVEs (data/cve/cve_database.json)
- IOCs (data/iocs.json)
- YARA rules (policies/yara/)
- MITRE ATT&CK mapping
- Documentação (docs/)
- Logs de incidentes anteriores

Não usa embeddings externos (chroma/pinecone) — é puro Python.
Para produção, substituir por vector store real.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("goodware.llm.rag")


def tokenize(text: str) -> List[str]:
    """Tokenização simples."""
    text = text.lower()
    # Manter alfanumérico
    text = re.sub(r"[^a-z0-9_àáâãçéêíóôõú ]+", " ", text)
    tokens = text.split()
    # Remove stopwords
    stopwords = {"de", "a", "o", "e", "é", "em", "para", "com", "que", "do", "da", "no", "na"}
    return [t for t in tokens if len(t) > 2 and t not in stopwords]


class Document:
    """Documento indexado."""

    def __init__(self, doc_id: str, content: str, metadata: Dict[str, Any] = None):
        self.id = doc_id
        self.content = content
        self.metadata = metadata or {}
        self.tokens: List[str] = []
        self.tf: Counter = Counter()
        self._tokenize()

    def _tokenize(self):
        self.tokens = tokenize(self.content)
        self.tf = Counter(self.tokens)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "content": self.content, "metadata": self.metadata}


class SimpleVectorStore:
    """Vector store TF-IDF."""

    def __init__(self):
        self._docs: Dict[str, Document] = {}
        self._df: Counter = Counter()
        self._n_docs = 0
        self._lock = threading.RLock()

    def add(self, doc_id: str, content: str, metadata: Dict[str, Any] = None) -> None:
        """Adiciona documento."""
        with self._lock:
            doc = Document(doc_id, content, metadata)
            self._docs[doc_id] = doc
            self._n_docs += 1
            # Update IDF
            seen = set()
            for token in doc.tokens:
                if token not in seen:
                    self._df[token] += 1
                    seen.add(token)

    def _tfidf(self, doc: Document, term: str) -> float:
        """TF-IDF score."""
        if term not in doc.tf:
            return 0.0
        tf = 1 + math.log(doc.tf[term])  # log normalisation
        df = self._df.get(term, 1)
        idf = math.log((self._n_docs + 1) / (df + 1)) + 1
        return tf * idf

    def search(self, query: str, top_k: int = 5) -> List[Tuple[Document, float]]:
        """Procura por query, devolve top_k docs com score."""
        query_tokens = tokenize(query)
        if not query_tokens:
            return []

        results = []
        with self._lock:
            docs = list(self._docs.values())
        for doc in docs:
            score = 0.0
            for term in query_tokens:
                score += self._tfidf(doc, term)
            if score > 0:
                results.append((doc, score))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def count(self) -> int:
        return self._n_docs

    def clear(self) -> None:
        with self._lock:
            self._docs.clear()
            self._df.clear()
            self._n_docs = 0


class GoodwareRAG:
    """RAG indexado sobre knowledge base do Goodware."""

    def __init__(self, root: str = "/workspace/goodware-v3"):
        self._root = Path(root)
        self._store = SimpleVectorStore()
        self._indexed = False
        self._lock = threading.RLock()

    def index(self) -> None:
        """Indexa toda a knowledge base."""
        with self._lock:
            if self._indexed:
                return
            log.info("Indexando knowledge base...")
            self._index_cves()
            self._index_iocs()
            self._index_yara_rules()
            self._index_mitre()
            self._index_docs()
            self._indexed = True
            log.info(f"Indexado: {self._store.count()} documentos")

    def _index_cves(self) -> None:
        cve_path = self._root / "data/cve/cve_database.json"
        if not cve_path.exists():
            return
        try:
            with open(cve_path) as f:
                data = json.load(f)
            for cve in data.get("cves", []):
                text = (
                    f"{cve.get('cve_id','')} {cve.get('vendor','')} {cve.get('product','')} "
                    f"{cve.get('severity','')} {cve.get('description','')}"
                )
                self._store.add(f"cve-{cve.get('cve_id','')}", text, cve)
        except Exception as e:
            log.warning(f"Failed to index CVEs: {e}")

    def _index_iocs(self) -> None:
        iocs_path = self._root / "data/iocs.json"
        if not iocs_path.exists():
            return
        try:
            with open(iocs_path) as f:
                data = json.load(f)
            for category, items in data.items():
                for item in items:
                    self._store.add(f"ioc-{category}-{item[:50]}", f"{category} {item}", {"type": category, "value": item})
        except Exception as e:
            log.warning(f"Failed to index IOCs: {e}")

    def _index_yara_rules(self) -> None:
        yara_dir = self._root / "policies/yara"
        if not yara_dir.exists():
            return
        for yar_file in yara_dir.rglob("*.yar*"):
            try:
                text = yar_file.read_text()
                self._store.add(f"yara-{yar_file.stem}", text, {"path": str(yar_file)})
            except Exception:
                pass

    def _index_mitre(self) -> None:
        mitre_path = self._root / "data/mitre_attack_mapping.json"
        if not mitre_path.exists():
            return
        try:
            with open(mitre_path) as f:
                data = json.load(f)
            for tech in data.get("techniques", []):
                text = f"{tech.get('id','')} {tech.get('name','')} {tech.get('tactic','')} {tech.get('detection','')}"
                self._store.add(f"mitre-{tech.get('id','')}", text, tech)
        except Exception:
            pass

    def _index_docs(self) -> None:
        docs_dir = self._root / "docs"
        if not docs_dir.exists():
            return
        for md_file in docs_dir.rglob("*.md"):
            try:
                text = md_file.read_text()
                self._store.add(f"doc-{md_file.stem}", text, {"path": str(md_file)})
            except Exception:
                pass

    def query(self, q: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Procura e devolve resultados formatados."""
        self.index()
        results = self._store.search(q, top_k=top_k)
        return [
            {
                "id": doc.id,
                "score": float(score),
                "content": doc.content[:500],
                "metadata": doc.metadata,
            }
            for doc, score in results
        ]

    def augment_prompt(self, query: str, top_k: int = 3) -> str:
        """Gera prompt aumentado com contexto relevante."""
        results = self.query(query, top_k)
        if not results:
            return query
        ctx_parts = []
        for r in results:
            ctx_parts.append(f"[{r['id']}]\n{r['content']}")
        ctx = "\n\n---\n\n".join(ctx_parts)
        return (
            f"Contexto relevante (RAG):\n\n{ctx}\n\n"
            f"---\n\nPergunta original:\n{query}"
        )


_rag: Optional[GoodwareRAG] = None


def get_rag() -> GoodwareRAG:
    global _rag
    if _rag is None:
        _rag = GoodwareRAG()
        _rag.index()
    return _rag
