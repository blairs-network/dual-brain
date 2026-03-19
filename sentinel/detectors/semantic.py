"""
SENTINEL — Detector: Semantic Drift
Compares task intent against model output using vector similarity.
A successful injection often shifts the topic — measurable as embedding drift.
Uses lightweight local embeddings (no external API call required).
"""
import re
import math
from collections import Counter
from sentinel.core.models import (
    Task, ToolCall, InjectionFlag, FlagType, Severity
)

# Drift thresholds — tunable
DRIFT_THRESHOLD_MEDIUM   = 0.55   # Flag as MEDIUM  (raised from 0.35)
DRIFT_THRESHOLD_HIGH     = 0.72   # Flag as HIGH    (raised from 0.55)
DRIFT_THRESHOLD_CRITICAL = 0.85   # Flag as CRITICAL (raised from 0.72)

# Minimum token count — skip drift check if text is too short
# Short texts naturally have high cosine distance due to sparse vocabulary
MIN_TASK_TOKENS   = 6
MIN_OUTPUT_TOKENS = 15


# ── Lightweight TF-IDF-style embedding ───────────────────────────────────────
# No external deps, no API calls. Fast enough for real-time detection.
# Not as accurate as a proper embedding model but catches gross semantic drift.

STOPWORDS = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "this", "that", "these", "those", "i", "you",
    "he", "she", "it", "we", "they", "me", "him", "her", "us", "them",
    "my", "your", "his", "its", "our", "their", "what", "which", "who",
    "please", "just", "can", "get", "make", "use", "need", "want",
}


def _tokenize(text: str) -> list[str]:
    """Simple word tokenizer with stopword removal."""
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    return [w for w in words if w not in STOPWORDS]


def _tfidf_vector(text: str, vocab: set[str]) -> dict[str, float]:
    """Build a TF-IDF-ish vector from text against a vocabulary."""
    tokens = _tokenize(text)
    if not tokens:
        return {}
    tf = Counter(tokens)
    total = len(tokens)
    return {word: count / total
            for word, count in tf.items()
            if word in vocab}


def _cosine_distance(v1: dict, v2: dict) -> float:
    """Cosine distance between two sparse vectors. 0=identical, 1=orthogonal."""
    if not v1 or not v2:
        return 1.0  # no overlap = maximum distance

    vocab  = set(v1) | set(v2)
    dot    = sum(v1.get(w, 0) * v2.get(w, 0) for w in vocab)
    norm1  = math.sqrt(sum(x**2 for x in v1.values()))
    norm2  = math.sqrt(sum(x**2 for x in v2.values()))

    if norm1 == 0 or norm2 == 0:
        return 1.0

    similarity = dot / (norm1 * norm2)
    return round(1.0 - min(1.0, max(0.0, similarity)), 4)


def _build_vocab(*texts: str) -> set[str]:
    """Build combined vocabulary from all texts."""
    vocab = set()
    for text in texts:
        vocab.update(_tokenize(text))
    return vocab


def check_semantic_drift(
    task: Task,
    model_output: str,
    tool_results: list[str] | None = None,
) -> list[InjectionFlag]:
    """
    Compares task description embedding against model output embedding.
    High cosine distance = the output diverged significantly from the task.
    This catches injections that make the model produce content unrelated
    to what was asked.
    """
    flags = []

    task_text   = task.description
    output_text = model_output

    if not task_text.strip() or not output_text.strip():
        return flags

    # Skip if texts are too short — sparse vocab causes false positives
    if (len(_tokenize(task_text))   < MIN_TASK_TOKENS or
            len(_tokenize(output_text)) < MIN_OUTPUT_TOKENS):
        return flags

    vocab    = _build_vocab(task_text, output_text)
    v_task   = _tfidf_vector(task_text, vocab)
    v_output = _tfidf_vector(output_text, vocab)
    distance = _cosine_distance(v_task, v_output)

    if distance >= DRIFT_THRESHOLD_CRITICAL:
        severity = Severity.CRITICAL
    elif distance >= DRIFT_THRESHOLD_HIGH:
        severity = Severity.HIGH
    elif distance >= DRIFT_THRESHOLD_MEDIUM:
        severity = Severity.MEDIUM
    else:
        return flags  # within acceptable drift

    flags.append(InjectionFlag(
        flag_type = FlagType.SEMANTIC_DRIFT,
        severity  = severity,
        detail    = (f"Output diverged from task intent "
                     f"(drift score: {distance:.3f}, "
                     f"threshold: {DRIFT_THRESHOLD_MEDIUM})"),
        evidence  = (f"Task: '{task_text[:80]}...' → "
                     f"Output: '{output_text[:80]}...'")
    ))

    return flags


def check_tool_result_drift(
    task: Task,
    tool_calls: list[ToolCall],
) -> list[InjectionFlag]:
    """
    Checks if any individual tool's result drifted semantically from the task.
    Catches cases where injected content in a single tool result is the vector.
    Each tool result is compared independently against task intent.
    """
    flags = []
    task_text = task.description

    for tc in tool_calls:
        if not tc.result or len(tc.result) < 50:
            continue

        result_tokens = _tokenize(tc.result)
        task_tokens   = _tokenize(task_text)

        # Skip if either side is too short — sparse vocab causes false positives
        if len(result_tokens) < MIN_TASK_TOKENS:
            continue

        # Skip if there is zero vocabulary overlap (distance = 1.0 trivially)
        # Tool results often use domain terms not in the task description
        # A score of 1.0 from pure vocabulary mismatch is not meaningful
        vocab    = _build_vocab(task_text, tc.result)
        overlap  = set(result_tokens) & set(task_tokens)
        if len(overlap) == 0:
            continue

        v_task   = _tfidf_vector(task_text, vocab)
        v_result = _tfidf_vector(tc.result, vocab)
        distance = _cosine_distance(v_task, v_result)

        # Tool results naturally diverge more — higher threshold
        tool_threshold = DRIFT_THRESHOLD_HIGH + 0.20

        if distance >= tool_threshold:
            flags.append(InjectionFlag(
                flag_type = FlagType.SEMANTIC_DRIFT,
                severity  = Severity.MEDIUM,
                detail    = (f"Tool '{tc.tool}' result drifted from task "
                             f"(score: {distance:.3f})"),
                tool_call = tc,
                evidence  = tc.result[:200]
            ))

    return flags


def compute_risk_score(
    flags: list[InjectionFlag],
    tool_calls: list[ToolCall],
    task: Task,
) -> float:
    """
    Compute a 0.0–1.0 risk score from all available signals.
    Used for prioritization and threat intelligence.
    """
    if not flags:
        return 0.0

    # Severity weights
    severity_weights = {
        Severity.CRITICAL: 0.40,
        Severity.HIGH:     0.25,
        Severity.MEDIUM:   0.12,
        Severity.LOW:      0.05,
    }

    # Flag type multipliers — some patterns are more dangerous
    type_multipliers = {
        FlagType.UNAUTHORIZED_EXFIL:     1.5,
        FlagType.ROLE_OVERRIDE_ATTEMPT:  1.4,
        FlagType.LATERAL_MOVE_ATTEMPT:   1.4,
        FlagType.CREDENTIAL_ACCESS:      1.5,
        FlagType.PERSISTENCE_ATTEMPT:    1.3,
        FlagType.MULTI_HOP_INJECTION:    1.3,
        FlagType.SILENT_ACTION:          1.2,
    }

    score = 0.0
    for flag in flags:
        base       = severity_weights.get(flag.severity, 0.05)
        multiplier = type_multipliers.get(flag.flag_type, 1.0)
        score      += base * multiplier

    # Bonus for multiple flags (correlated signals = more confident)
    if len(flags) > 2:
        score *= 1.0 + (len(flags) - 2) * 0.05

    # Bonus for external comms tools in call chain
    external_calls = sum(1 for tc in tool_calls
                         if tc.tool in {"http_request", "send_email",
                                        "post_message", "fetch_url"})
    if external_calls > 0:
        score *= 1.0 + external_calls * 0.08

    return round(min(1.0, score), 4)
