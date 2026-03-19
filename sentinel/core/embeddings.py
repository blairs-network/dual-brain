"""
SENTINEL — Embedding Interface
Pluggable backend for semantic similarity.

Priority order:
  1. sentence-transformers (best accuracy, local, no API cost)
  2. Ollama nomic-embed-text (local, via Ollama)
  3. TF-IDF fallback (no dependencies, always available)

Drop-in: the rest of SENTINEL calls embed() and cosine_distance()
and doesn't care which backend is running.
"""
import math
import re
from collections import Counter
from typing import Protocol, runtime_checkable


# ── Backend protocol ──────────────────────────────────────────────────────────

@runtime_checkable
class EmbeddingBackend(Protocol):
    name: str
    def encode(self, text: str) -> list[float]: ...


# ── TF-IDF backend (always available) ────────────────────────────────────────

STOPWORDS = {
    "a","an","the","and","or","but","in","on","at","to","for","of","with",
    "by","from","is","are","was","were","be","been","have","has","had","do",
    "does","did","will","would","could","should","may","might","this","that",
    "these","those","i","you","he","she","it","we","they","me","him","her",
    "us","them","my","your","his","its","our","their","what","which","who",
    "please","just","can","get","make","use","need","want","not","no","if",
}


class TFIDFBackend:
    name = "tfidf"
    _vocab: set[str] = set()
    _dim   = 512

    def _tokenize(self, text: str) -> list[str]:
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        return [w for w in words if w not in STOPWORDS]

    def fit(self, texts: list[str]) -> None:
        """Optionally pre-build vocab from a corpus."""
        for t in texts:
            self._vocab.update(self._tokenize(t))

    def encode(self, text: str) -> list[float]:
        tokens = self._tokenize(text)
        if not tokens:
            return [0.0] * 50

        tf     = Counter(tokens)
        total  = len(tokens)
        vocab  = self._vocab or set(tokens)
        vec    = {w: c/total for w, c in tf.items() if w in vocab or not self._vocab}
        return list(vec.values())[:self._dim]


# ── Ollama embed backend ──────────────────────────────────────────────────────

class OllamaEmbedBackend:
    name = "ollama"

    def __init__(self, model: str = "nomic-embed-text"):
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import ollama
                self._client = ollama
            except ImportError:
                raise RuntimeError("ollama package not installed")
        return self._client

    def encode(self, text: str) -> list[float]:
        client = self._get_client()
        resp   = client.embeddings(model=self.model, prompt=text)
        return resp["embedding"]

    @classmethod
    def available(cls) -> bool:
        try:
            import ollama
            ollama.embeddings(model="nomic-embed-text", prompt="test")
            return True
        except Exception:
            return False


# ── sentence-transformers backend ────────────────────────────────────────────

class SentenceTransformerBackend:
    name = "sentence-transformers"

    def __init__(self, model: str = "all-MiniLM-L6-v2"):
        self.model_name = model
        self._model = None

    def _load(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
        return self._model

    def encode(self, text: str) -> list[float]:
        model = self._load()
        return model.encode(text).tolist()

    @classmethod
    def available(cls) -> bool:
        try:
            import sentence_transformers
            return True
        except ImportError:
            return False


# ── Auto-select best available backend ───────────────────────────────────────

def get_best_backend() -> EmbeddingBackend:
    """
    Returns the best available embedding backend.
    Tries: sentence-transformers → Ollama → TF-IDF
    """
    if SentenceTransformerBackend.available():
        print("[sentinel:embed] Using sentence-transformers backend")
        return SentenceTransformerBackend()

    if OllamaEmbedBackend.available():
        print("[sentinel:embed] Using Ollama nomic-embed-text backend")
        return OllamaEmbedBackend()

    print("[sentinel:embed] Using TF-IDF fallback backend")
    return TFIDFBackend()


# ── Similarity functions ──────────────────────────────────────────────────────

def cosine_distance(v1: list[float], v2: list[float]) -> float:
    """Cosine distance between two dense vectors. 0=identical, 1=orthogonal."""
    if not v1 or not v2:
        return 1.0

    # Align lengths (TF-IDF vectors may differ)
    min_len = min(len(v1), len(v2))
    v1, v2  = v1[:min_len], v2[:min_len]

    dot   = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(x**2 for x in v1))
    norm2 = math.sqrt(sum(x**2 for x in v2))

    if norm1 == 0 or norm2 == 0:
        return 1.0

    sim = dot / (norm1 * norm2)
    return round(1.0 - min(1.0, max(0.0, sim)), 4)


def cosine_similarity(v1: list[float], v2: list[float]) -> float:
    return round(1.0 - cosine_distance(v1, v2), 4)


# ── Module-level singleton ────────────────────────────────────────────────────

_backend: EmbeddingBackend | None = None


def get_backend() -> EmbeddingBackend:
    global _backend
    if _backend is None:
        _backend = get_best_backend()
    return _backend


def embed(text: str) -> list[float]:
    """Encode text using the best available backend."""
    return get_backend().encode(text)


def semantic_distance(text1: str, text2: str) -> float:
    """Compute cosine distance between two texts. 0=identical, 1=orthogonal."""
    return cosine_distance(embed(text1), embed(text2))
