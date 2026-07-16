"""Redaction boundary for safe activity summaries and metadata."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence


class UnsafeActivityContentError(ValueError):
    """Raised when content attempts to expose hidden reasoning."""


_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|authorization|cookie|session|credential)",
    re.IGNORECASE,
)
_HIDDEN_REASONING_KEY = re.compile(
    r"(?:chain[_-]?of[_-]?thought|hidden[_-]?reasoning|private[_-]?reasoning|"
    r"internal[_-]?monologue|system[_-]?prompt|developer[_-]?message|raw[_-]?prompt)",
    re.IGNORECASE,
)
_HIDDEN_REASONING_TEXT = re.compile(
    r"\b(?:chain[- ]of[- ]thought|hidden reasoning|private reasoning|"
    r"internal monologue|system prompt|developer message)\b",
    re.IGNORECASE,
)
_SECRET_PATTERNS = (
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.IGNORECASE),
    re.compile(r"\b(?:sk|pk)_[A-Za-z0-9_-]{20,}\b"),
)
_MAX_STRING_LENGTH = 4_000
_MAX_DEPTH = 8


def _redact_string(value: str) -> str:
    cleaned = value[:_MAX_STRING_LENGTH]
    for pattern in _SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    if len(value) > _MAX_STRING_LENGTH:
        cleaned += "…[TRUNCATED]"
    return cleaned


def sanitize_summary(summary: str) -> str:
    """Return a concise operational summary without hidden reasoning or secrets."""
    cleaned = _redact_string(summary.strip())
    if not cleaned:
        raise UnsafeActivityContentError("activity summary cannot be empty")
    if _HIDDEN_REASONING_TEXT.search(cleaned):
        raise UnsafeActivityContentError(
            "activity summaries must not expose hidden or private reasoning"
        )
    return cleaned


def redact_metadata(value: object, *, _depth: int = 0) -> object:
    """Recursively redact secrets and omit hidden-reasoning fields."""
    if _depth > _MAX_DEPTH:
        return "[MAX_DEPTH_REACHED]"
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            if _HIDDEN_REASONING_KEY.search(key):
                result[key] = "[OMITTED]"
            elif _SENSITIVE_KEY.search(key):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_metadata(child, _depth=_depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return [redact_metadata(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, bytes):
        return "[BINARY_OMITTED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_string(str(value))
