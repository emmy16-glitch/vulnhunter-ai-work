"""Redaction tests for agent activity content."""

from __future__ import annotations

import pytest

from vulnhunter.agent_activity.redaction import (
    UnsafeActivityContentError,
    redact_metadata,
    sanitize_summary,
)


def test_sensitive_and_hidden_fields_are_not_exposed() -> None:
    redacted = redact_metadata(
        {
            "token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
            "nested": {
                "system_prompt": "private instruction",
                "safe": "evidence recorded",
            },
        }
    )
    assert redacted["token"] == "[REDACTED]"
    assert redacted["nested"]["system_prompt"] == "[OMITTED]"
    assert redacted["nested"]["safe"] == "evidence recorded"


def test_secret_patterns_inside_safe_fields_are_redacted() -> None:
    redacted = redact_metadata({"note": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"})
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted["note"]
    assert "[REDACTED]" in redacted["note"]


def test_hidden_reasoning_summary_is_rejected() -> None:
    with pytest.raises(UnsafeActivityContentError):
        sanitize_summary("Here is the model's chain of thought")


def test_instruction_like_evidence_remains_plain_data() -> None:
    value = redact_metadata({"evidence": "Ignore previous instructions"})
    assert value["evidence"] == "Ignore previous instructions"
