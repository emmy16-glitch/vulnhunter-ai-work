"""Deterministic, privacy-conscious feature engineering for observations."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from urllib.parse import unquote, urlsplit

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
_SENSITIVE_CONTEXT_TERMS = frozenset(
    {
        "account",
        "admin",
        "auth",
        "backup",
        "config",
        "dashboard",
        "debug",
        "error",
        "files",
        "internal",
        "login",
        "operations",
        "private",
        "secure",
        "signin",
    }
)
_PUBLIC_CONTEXT_TERMS = frozenset(
    {
        "about",
        "assets",
        "blog",
        "docs",
        "documentation",
        "guide",
        "help",
        "public",
        "static",
        "widget",
    }
)
_FIXED_FEATURES = (
    "url:https",
    "url:has_query",
    "url:path_depth",
    "url:path_sensitive_term_count",
    "url:path_public_term_count",
    "url:path_has_login",
    "url:path_has_admin",
    "url:path_has_private",
    "url:path_has_error",
    "url:path_has_files",
    "url:path_has_backup",
    "url:path_has_docs",
    "url:path_has_guide",
    "url:path_has_widget",
    "url:path_has_about",
    "evidence:key_count",
    "evidence:string_count",
    "evidence:number_count",
    "evidence:missing_headers_count",
    "evidence:detected_indicators_count",
    "evidence:status_2xx",
    "evidence:status_3xx",
    "evidence:status_4xx",
    "evidence:status_5xx",
    "evidence:missing_csp",
    "evidence:missing_x_content_type_options",
    "evidence:missing_referrer_policy",
    "evidence:missing_hsts",
    "evidence:x_frame_options_present",
    "evidence:csp_frame_ancestors_present",
    "evidence:discloses_server",
    "evidence:discloses_x_powered_by",
    "evidence:debug_traceback",
    "evidence:debug_stack_trace",
    "evidence:debug_uncaught_exception",
    "evidence:debug_fatal_error",
    "evidence:directory_title_index",
    "evidence:directory_mentions_private",
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
        schema_version=2,
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


def _normalised_strings(value: object) -> set[str]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {str(item).strip().lower() for item in value if str(item).strip()}


def _normalised_mapping_keys(value: object) -> set[str]:
    if not isinstance(value, Mapping):
        return set()
    return {str(key).strip().lower() for key in value}


def _context_terms(example: ObservationInput) -> set[str]:
    """Extract only predeclared semantic terms, never arbitrary path values."""
    parsed = urlsplit(example.url)
    text_parts = [unquote(parsed.path).lower()]

    for key in ("page_title", "heading"):
        value = example.evidence.get(key)
        if isinstance(value, str):
            text_parts.append(value.lower())

    tokens = set(_TOKEN_PATTERN.findall(" ".join(text_parts)))
    return tokens & (_SENSITIVE_CONTEXT_TERMS | _PUBLIC_CONTEXT_TERMS)


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
    context_terms = _context_terms(example)
    missing_headers = _normalised_strings(example.evidence.get("missing_headers"))
    detected_indicators = _normalised_strings(example.evidence.get("detected_indicators"))
    disclosed_headers = _normalised_mapping_keys(example.evidence.get("headers"))
    page_title = str(example.evidence.get("page_title", "")).lower()
    heading = str(example.evidence.get("heading", "")).lower()

    fixed_values = {
        "url:https": 1.0 if parsed_url.scheme.lower() == "https" else 0.0,
        "url:has_query": 1.0 if parsed_url.query else 0.0,
        "url:path_depth": float(path_depth),
        "url:path_sensitive_term_count": float(len(context_terms & _SENSITIVE_CONTEXT_TERMS)),
        "url:path_public_term_count": float(len(context_terms & _PUBLIC_CONTEXT_TERMS)),
        "url:path_has_login": 1.0 if "login" in context_terms or "signin" in context_terms else 0.0,
        "url:path_has_admin": 1.0 if "admin" in context_terms else 0.0,
        "url:path_has_private": 1.0 if "private" in context_terms else 0.0,
        "url:path_has_error": 1.0 if "error" in context_terms or "debug" in context_terms else 0.0,
        "url:path_has_files": 1.0 if "files" in context_terms else 0.0,
        "url:path_has_backup": 1.0 if "backup" in context_terms else 0.0,
        "url:path_has_docs": 1.0 if {"docs", "documentation"} & context_terms else 0.0,
        "url:path_has_guide": 1.0 if "guide" in context_terms else 0.0,
        "url:path_has_widget": 1.0 if "widget" in context_terms else 0.0,
        "url:path_has_about": 1.0 if "about" in context_terms else 0.0,
        "evidence:key_count": float(key_count),
        "evidence:string_count": float(string_count),
        "evidence:number_count": float(number_count),
        "evidence:missing_headers_count": float(len(missing_headers)),
        "evidence:detected_indicators_count": float(len(detected_indicators)),
        "evidence:status_2xx": 1.0 if status_code is not None and 200 <= status_code < 300 else 0.0,
        "evidence:status_3xx": 1.0 if status_code is not None and 300 <= status_code < 400 else 0.0,
        "evidence:status_4xx": 1.0 if status_code is not None and 400 <= status_code < 500 else 0.0,
        "evidence:status_5xx": 1.0 if status_code is not None and 500 <= status_code < 600 else 0.0,
        "evidence:missing_csp": 1.0 if "content-security-policy" in missing_headers else 0.0,
        "evidence:missing_x_content_type_options": (
            1.0 if "x-content-type-options" in missing_headers else 0.0
        ),
        "evidence:missing_referrer_policy": 1.0 if "referrer-policy" in missing_headers else 0.0,
        "evidence:missing_hsts": 1.0 if "strict-transport-security" in missing_headers else 0.0,
        "evidence:x_frame_options_present": (
            1.0 if example.evidence.get("x_frame_options_present") is True else 0.0
        ),
        "evidence:csp_frame_ancestors_present": (
            1.0 if example.evidence.get("csp_frame_ancestors_present") is True else 0.0
        ),
        "evidence:discloses_server": 1.0 if "server" in disclosed_headers else 0.0,
        "evidence:discloses_x_powered_by": 1.0 if "x-powered-by" in disclosed_headers else 0.0,
        "evidence:debug_traceback": (
            1.0 if any("traceback" in item for item in detected_indicators) else 0.0
        ),
        "evidence:debug_stack_trace": (
            1.0 if any("stack trace" in item for item in detected_indicators) else 0.0
        ),
        "evidence:debug_uncaught_exception": (
            1.0 if any("uncaught exception" in item for item in detected_indicators) else 0.0
        ),
        "evidence:debug_fatal_error": (
            1.0 if any("fatal error" in item for item in detected_indicators) else 0.0
        ),
        "evidence:directory_title_index": (
            1.0 if page_title.startswith("index of /") or heading.startswith("index of /") else 0.0
        ),
        "evidence:directory_mentions_private": (
            1.0 if "private" in page_title or "private" in heading else 0.0
        ),
    }

    try:
        values.extend(fixed_values[name] for name in schema.fixed_features)
    except KeyError as exc:
        raise ValueError(f"Unsupported feature in model schema: {exc.args[0]}") from exc
    return tuple(values)


def vectorize_many(
    examples: Iterable[ObservationInput],
    schema: FeatureSchema,
) -> tuple[tuple[float, ...], ...]:
    """Vectorise examples without changing their order."""
    return tuple(vectorize(example, schema) for example in examples)
