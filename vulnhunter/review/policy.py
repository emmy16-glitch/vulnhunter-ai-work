"""Validation rules for independent reviewers and adjudicators."""

from __future__ import annotations

import re

_REVIEWER_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")


def normalize_reviewer_id(value: str) -> str:
    """Return a stable pseudonymous reviewer identifier."""
    normalized = value.strip().lower()
    if not _REVIEWER_ID_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Reviewer IDs must be 2-64 lowercase letters, digits, dots, "
            "underscores, or hyphens, and must start with a letter or digit."
        )
    return normalized
