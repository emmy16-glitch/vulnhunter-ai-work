"""Application-service tests for bounded-agent activity timelines."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.agent_activity.models import ActivityEventDraft
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore

NOW = datetime(2026, 7, 10, tzinfo=UTC)


def _service(tmp_path: Path) -> AgentActivityService:
    return AgentActivityService(AppendOnlyActivityStore(tmp_path))


def test_record_redacts_metadata_before_persistence(tmp_path: Path) -> None:
    service = _service(tmp_path)
    event = service.record(
        ActivityEventDraft(
            run_id="run-example",
            timestamp=NOW,
            event_type="policy_check_started",
            summary="The policy check started.",
            run_state="checking_policy",
            source="policy",
            metadata={
                "token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
                "safe": "bounded action",
            },
        )
    )
    assert event.metadata["token"] == "[REDACTED]"
    assert event.metadata["safe"] == "bounded action"


def test_feed_reports_terminal_state_and_stops_polling_contract(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.record_transition(
        run_id="run-example",
        timestamp=NOW,
        event_type="run_completed",
        summary="The bounded run completed.",
        run_state="completed",
        source="runtime",
    )
    snapshot = service.feed("run-example")
    assert snapshot.terminal is True
    assert snapshot.run_state == "completed"


def test_stop_request_preserves_prior_events_and_is_not_success(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.record_transition(
        run_id="run-example",
        timestamp=NOW,
        event_type="run_created",
        summary="The bounded run was created.",
        run_state="created",
        source="runtime",
    )
    stop = service.request_stop(
        run_id="run-example",
        timestamp=NOW,
        actor_id="human-operator",
        reason="Authorization was revoked.",
    )
    snapshot = service.feed("run-example")
    assert len(snapshot.events) == 2
    assert stop.event_type == "stop_requested"
    assert stop.run_state == "stopping"
    assert snapshot.terminal is False
