"""Append-only storage tests for agent activity evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.agent_activity.models import ActivityEventDraft
from vulnhunter.agent_activity.store import (
    ActivityIntegrityError,
    ActivityStoreError,
    AppendOnlyActivityStore,
)


def _draft(sequence_offset: int, event_type: str = "run_created") -> ActivityEventDraft:
    return ActivityEventDraft(
        run_id="run-example",
        timestamp=datetime(2026, 7, 10, tzinfo=UTC) + timedelta(seconds=sequence_offset),
        event_type=event_type,
        summary=f"Operational event {sequence_offset} was recorded.",
        run_state="created" if sequence_offset == 0 else "planning",
        source="runtime",
    )


def test_append_assigns_contiguous_sequence_and_hash_chain(tmp_path: Path) -> None:
    store = AppendOnlyActivityStore(tmp_path)
    first = store.append(_draft(0))
    second = store.append(_draft(1, "planning_started"))
    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_event_sha256 == first.event_sha256
    assert store.verify("run-example").valid is True


def test_read_after_supports_nonduplicating_polling(tmp_path: Path) -> None:
    store = AppendOnlyActivityStore(tmp_path)
    first = store.append(_draft(0))
    second = store.append(_draft(1, "planning_started"))
    events = store.read_after("run-example", after_sequence=first.sequence)
    assert events == (second,)


def test_corruption_is_detected_before_new_append(tmp_path: Path) -> None:
    store = AppendOnlyActivityStore(tmp_path)
    store.append(_draft(0))
    path = tmp_path / "run-example.jsonl"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["summary"] = "tampered"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    assert store.verify("run-example").valid is False
    with pytest.raises(ActivityIntegrityError):
        store.append(_draft(1, "planning_started"))


def test_path_traversal_run_id_is_rejected(tmp_path: Path) -> None:
    store = AppendOnlyActivityStore(tmp_path)
    with pytest.raises(ActivityStoreError):
        store.read_after("../escape")
