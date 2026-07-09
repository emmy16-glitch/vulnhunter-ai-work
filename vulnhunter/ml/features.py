"""Deterministic, privacy-conscious feature engineering for observations."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from vulnhunter.ml.models import FeatureSchema, ObservationInput, TrainingExample

_TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_]{2,30}")
_STOP_WORDS = frozenset(
    {
        "and",
        "are",
        "for",
        "from",
        "has",
        "have",
        "into",
        "not",
        "that",
        "the",
        "their",
        "this",
        "through",
        "was",
        "were",
        "with",
    }
)
_FIXED_FEATURES = (
    "url:https",
    "url:has_query",
    "url:path_depth",
    "evidence:key_count",
    "evidence:string_count",
    "evidence:number_count",
    "evidence:missing_headers_count",
    "evidence:detected_indicators_count",
    "evidence:status_4xx",
    "evidence:status_5xx",
)


def _tokens(example: ObservationInput) -> set[str]:
    """Tokenise only redacted title and description text."""
    text = f"{example.title} {example.description}".lower()
    return {token for token in _TOKEN_PATTERN.findall(text) if token not in _STOP_WORDS}


def build_feature_schema(
    examples: Sequence[TrainingExample],
    *,
    maximum_tokens: int = 128,
    minimum_document_frequency: int = 1,
) -> FeatureSchema:
    """Build a deterministic schema from training examples only."""
    if maximum_tokens < 0 or maximum_tokens > 2_000:
        raise ValueError("maximum_tokens must be between 0 and 2000.")

    if minimum_document_frequency < 1:
        raise ValueError("minimum_document_frequency must be at least 1.")

    categories = tuple(sorted({example.category for example in examples}))
    document_frequency: Counter[str] = Counter()

    for example in examples:
        document_frequency.update(_tokens(example))

    tokens = tuple(
        token
        for token, count in sorted(
            document_frequency.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count >= minimum_document_frequency
    )[:maximum_tokens]

    return FeatureSchema(
        categories=categories,
        tokens=tokens,
        fixed_features=_FIXED_FEATURES,
    )


def _count_evidence_values(value: object) -> tuple[int, int, int]:
    """Return recursive key, string, and numeric counts."""
    if isinstance(value, Mapping):
        key_count = len(value)
        string_count = 0
        number_count = 0
        for nested in value.values():
            nested_keys, nested_strings, nested_numbers = _count_evidence_values(nested)
            key_count += nested_keys
            string_count += nested_strings
            number_count += nested_numbers
        return key_count, string_count, number_count

    if isinstance(value, (list, tuple, set)):
        totals = [0, 0, 0]
        for nested in value:
            nested_counts = _count_evidence_values(nested)
            totals = [left + right for left, right in zip(totals, nested_counts, strict=True)]
        return tuple(totals)  # type: ignore[return-value]

    if isinstance(value, str):
        return 0, 1, 0

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return 0, 0, 1

    return 0, 0, 0


def _sequence_length(value: object) -> int:
    return len(value) if isinstance(value, (list, tuple, set)) else 0


def _status_code(evidence: Mapping[str, object]) -> int | None:
    value = evidence.get("status_code")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def vectorize(example: ObservationInput, schema: FeatureSchema) -> tuple[float, ...]:
    """Transform one reviewed observation using a fixed feature order."""
    values: list[float] = []

    values.extend(
        1.0 if example.severity == severity else 0.0
        for severity in ("info", "low", "medium", "high")
    )
    values.extend(1.0 if example.category == category else 0.0 for category in schema.categories)

    example_tokens = _tokens(example)
    values.extend(1.0 if token in example_tokens else 0.0 for token in schema.tokens)

    parsed_url = urlsplit(example.url)
    path_depth = len([segment for segment in parsed_url.path.split("/") if segment])
    key_count, string_count, number_count = _count_evidence_values(example.evidence)
    status_code = _status_code(example.evidence)

    fixed_values = {
        "url:https": 1.0 if parsed_url.scheme.lower() == "https" else 0.0,
        "url:has_query": 1.0 if parsed_url.query else 0.0,
        "url:path_depth": float(path_depth),
        "evidence:key_count": float(key_count),
        "evidence:string_count": float(string_count),
        "evidence:number_count": float(number_count),
        "evidence:missing_headers_count": float(
            _sequence_length(example.evidence.get("missing_headers"))
        ),
        "evidence:detected_indicators_count": float(
            _sequence_length(example.evidence.get("detected_indicators"))
        ),
        "evidence:status_4xx": 1.0 if status_code is not None and 400 <= status_code < 500 else 0.0,
        "evidence:status_5xx": 1.0 if status_code is not None and 500 <= status_code < 600 else 0.0,
    }

    values.extend(fixed_values[name] for name in schema.fixed_features)
    return tuple(values)


def vectorize_many(
    examples: Iterable[ObservationInput],
    schema: FeatureSchema,
) -> tuple[tuple[float, ...], ...]:
    """Vectorise examples without changing their order."""
    return tuple(vectorize(example, schema) for example in examples)
