"""Model tests for bounded-agent activity events."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnhunter.agent_activity.models import ActivityEventDraft


def _payload() -> dict[str, object]:
    return {
        "run_id": "run-example",
        "timestamp": datetime(2026, 7, 10, tzinfo=UTC),
        "event_type": "run_created",
        "summary": "The bounded run was created.",
        "run_state": "created",
        "source": "runtime",
    }


def test_draft_is_strict_and_timezone_aware() -> None:
    draft = ActivityEventDraft.model_validate(_payload())
    assert draft.timestamp.tzinfo is not None
    payload = _payload()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        ActivityEventDraft.model_validate(payload)


def test_naive_timestamp_is_rejected() -> None:
    payload = _payload()
    payload["timestamp"] = datetime(2026, 7, 10)
    with pytest.raises(ValidationError, match="timezone-aware"):
        ActivityEventDraft.model_validate(payload)
