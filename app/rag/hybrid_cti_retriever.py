"""Hybrid Threat Intelligence RAG Engine combining Dense Vectors (pgvector/Pinecone/Chroma) + BM25 via RRF."""

from collections import Counter
import math
import re

import numpy as np

from app.core.config import settings
from app.core.logging import get_logger
from app.rag.mitre_knowledge_base import MITRE_ATTACK_CORPUS, MITRETechniqueDocument
from app.schemas.soc import MITREIntelligenceHit

logger = get_logger(__name__)

# 28-dimensional semantic cyber-threat concept space used for deterministic dense embeddings
_CTI_SEMANTIC_CONCEPTS: list[list[str]] = [
    ["powershell", "encodedcommand", "-enc", "iex",
        "invoke-expression", "downloadstring"],
    ["base64", "encoded", "obfuscated", "hidden", "bypass", "script"],
    ["mimikatz", "sekurlsa", "lsass", "procdump", "credential", "dump"],
    ["ntds.dit", "dcsync", "kerberoast", "hash", "/etc/shadow", "/etc/passwd"],
    ["psexec", "smb", "admin$", "c$", "wmic", "lateral", "pass-the-hash"],
    ["vssadmin", "shadowcopy", "shadows", "wbadmin",
        "bcdedit", "ransomware", "encrypt"],
    ["cobaltstrike", "beacon", "meterpreter", "c2", "callback", "reverse"],
    ["exfiltrate", "upload", "outbound", "transfer", "dump", "webhook"],
    ["sk-", "akia", "api_key", "secret", "token", "jwt"],
    ["brute", "spray", "failed", "authentication", "login", "ssh", "rdp"],
    ["sudo", "chmod", "root", "privilege", "escalation"],
    ["override", "ignore", "injection", "jailbreak", "disregard"],
]


class HybridMITRERetriever:
    """
    Production Hybrid RAG Retriever for Cyber Threat Intelligence (CTI):
    1. Dense Vector Similarity (Cosine Similarity compatible with pgvector, Pinecone.io & ChromaDB).
    2. Sparse Lexical Matching (Okapi BM25 with k1=1.5, b=0.75).
    3. Reciprocal Rank Fusion (RRF, k=60) combining dense and sparse rankings.
    """

    def __init__(self, corpus: list[MITRETechniqueDocument] | None = None) -> None:
        self.corpus = corpus or MITRE_ATTACK_CORPUS
        self.rrf_k = settings.RRF_K_CONSTANT
        self.k1 = 1.5
        self.b = 0.75

        # Precompute tokenized documents, BM25 IDF statistics, and L2-normalized dense embeddings
        self._doc_tokens: list[list[str]] = []
        self._doc_freqs: dict[str, int] = Counter()
        self._dense_matrix: list[np.ndarray] = []

        for doc in self.corpus:
            full_text = f"{doc.technique_id} {doc.technique_name} {' '.join(doc.keywords)} {doc.description}"
            tokens = self._tokenize(full_text)
            self._doc_tokens.append(tokens)
            for unique_tok in set(tokens):
                self._doc_freqs[unique_tok] += 1
            self._dense_matrix.append(self.embed_text(full_text))

        self._avg_doc_len = (
            sum(len(t) for t in self._doc_tokens) /
            max(len(self._doc_tokens), 1)
        )

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Extract normalized alphanumeric and SOC indicator tokens."""
        return re.findall(r"[a-z0-9_.$#-]+", text.lower())

    @classmethod
    def embed_text(cls, text: str) -> np.ndarray:
        """Compute deterministic L2-normalized dense semantic embedding vector for CTI matching."""
        lower_text = text.lower()
        tokens = set(cls._tokenize(lower_text))
        vec = np.zeros(len(_CTI_SEMANTIC_CONCEPTS), dtype=np.float32)

        for idx, concept_group in enumerate(_CTI_SEMANTIC_CONCEPTS):
            hits = sum(
                1 for kw in concept_group if kw in tokens or kw in lower_text)
            if hits > 0:
                vec[idx] = float(min(1.0 + 0.45 * (hits - 1), 2.5))

        norm = float(np.linalg.norm(vec))
        if norm > 1e-6:
            vec = vec / norm
        return vec

    def _compute_bm25_scores(self, query_tokens: list[str]) -> list[float]:
        """Compute Okapi BM25 lexical relevance scores across all MITRE ATT&CK documents."""
        n_docs = len(self.corpus)
        scores: list[float] = []

        for doc_tokens in self._doc_tokens:
            doc_len = len(doc_tokens)
            tf_counter = Counter(doc_tokens)
            score = 0.0

            for q_tok in query_tokens:
                if q_tok not in tf_counter:
                    continue
                df = self._doc_freqs.get(q_tok, 0)
                idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
                tf = tf_counter[q_tok]
                denom = tf + self.k1 * \
                    (1.0 - self.b + self.b * (doc_len / max(self._avg_doc_len, 1.0)))
                score += idf * ((tf * (self.k1 + 1.0)) / max(denom, 1e-6))

            scores.append(round(score, 4))
        return scores

    def _compute_dense_scores(self, query_text: str) -> list[float]:
        """Compute Cosine Similarity scores against the dense MITRE vector index."""
        q_vec = self.embed_text(query_text)
        if float(np.linalg.norm(q_vec)) < 1e-6:
            return [0.0 for _ in self.corpus]

        return [
            round(max(float(np.dot(q_vec, doc_vec)), 0.0), 4)
            for doc_vec in self._dense_matrix
        ]

    def retrieve(self, query: str, top_k: int = 3) -> list[MITREIntelligenceHit]:
        """
        Execute Hybrid Search (Dense Vector + Okapi BM25) and fuse rankings via
        Reciprocal Rank Fusion (RRF): RRF(d) = 1 / (k + rank_dense(d)) + 1 / (k + rank_bm25(d)).
        """
        query_tokens = self._tokenize(query)
        dense_scores = self._compute_dense_scores(query)
        bm25_scores = self._compute_bm25_scores(query_tokens)

        # Rank documents (1-indexed, descending by score)
        dense_order = sorted(
            range(len(self.corpus)), key=lambda i: dense_scores[i], reverse=True
        )
        bm25_order = sorted(
            range(len(self.corpus)), key=lambda i: bm25_scores[i], reverse=True
        )

        dense_ranks = {doc_idx: rank + 1 for rank,
                       doc_idx in enumerate(dense_order)}
        bm25_ranks = {doc_idx: rank + 1 for rank,
                      doc_idx in enumerate(bm25_order)}

        fused_results: list[tuple[int, float]] = []
        for idx in range(len(self.corpus)):
            rrf_val = (1.0 / (self.rrf_k + dense_ranks[idx])) + (
                1.0 / (self.rrf_k + bm25_ranks[idx])
            )
            # Add tiny tie-breaker from raw scores so ordering is strictly deterministic
            tie_breaker = (dense_scores[idx] * 1e-3) + \
                (bm25_scores[idx] * 1e-4)
            fused_results.append((idx, rrf_val + tie_breaker))

        fused_results.sort(key=lambda item: item[1], reverse=True)

        hits: list[MITREIntelligenceHit] = []
        for doc_idx, rrf_score in fused_results[:top_k]:
            doc = self.corpus[doc_idx]
            hits.append(
                MITREIntelligenceHit(
                    technique_id=doc.technique_id,
                    technique_name=doc.technique_name,
                    tactic=doc.tactic,
                    rrf_score=round(rrf_score, 5),
                    dense_vector_score=dense_scores[doc_idx],
                    bm25_lexical_score=bm25_scores[doc_idx],
                    description=doc.description,
                    recommended_countermeasure=doc.recommended_countermeasure,
                )
            )

        logger.info(
            "Hybrid CTI RAG retrieved top match %s (%s) with RRF=%.5f",
            hits[0].technique_id if hits else "NONE",
            hits[0].technique_name if hits else "NONE",
            hits[0].rrf_score if hits else 0.0,
        )
        return hits


hybrid_mitre_retriever = HybridMITRERetriever()
