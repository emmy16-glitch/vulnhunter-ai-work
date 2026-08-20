from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from vulnhunter.realtime import consumers as consumer_module
from vulnhunter.realtime.consumers import AssessmentEventsConsumer


def _consumer(*, assessment_id: str = "") -> AssessmentEventsConsumer:
    consumer = object.__new__(AssessmentEventsConsumer)
    consumer.assessment_id = assessment_id
    consumer.route_assessment_id = "assessment-realtime"
    consumer.actor = None
    consumer.ticket_payload = None
    consumer.cursor = 0
    consumer._watch_task = None
    consumer.accept = AsyncMock()
    consumer.send_json = AsyncMock()
    consumer.close = AsyncMock()
    return consumer


def _tree(task_id: str, sequence: int, status: str = "running") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "task_id": task_id,
        "status": status,
        "last_sequence": sequence,
        "nodes": [],
    }


def _snapshot(task_id: str, sequence: int, *, terminal: bool = False) -> dict[str, object]:
    return {
        "events": [{"sequence": sequence, "event_type": "tool_progress"}],
        "last_sequence": sequence,
        "run_state": "completed" if terminal else "executing",
        "terminal": terminal,
        "activity_tree": _tree(task_id, sequence, "completed" if terminal else "running"),
    }


@pytest.mark.asyncio
async def test_connect_accepts_and_requests_a_ticket() -> None:
    consumer = _consumer()
    consumer.scope = {"url_route": {"kwargs": {"assessment_id": "assessment-realtime"}}}
    await consumer.connect()

    consumer.accept.assert_awaited_once()
    consumer.send_json.assert_awaited_once_with({"type": "realtime.ticket_required"})


@pytest.mark.asyncio
async def test_receive_rejects_malformed_messages_and_missing_tickets() -> None:
    consumer = _consumer()

    await consumer.receive_json([])
    consumer.close.assert_awaited_once_with(code=4400)

    consumer.close.reset_mock()
    await consumer.receive_json({})
    consumer.close.assert_awaited_once_with(code=4401)


@pytest.mark.asyncio
async def test_receive_rejects_reused_ticket_after_subject_is_bound() -> None:
    consumer = _consumer()
    consumer.assessment_id = "assessment-realtime"

    await consumer.receive_json({"ticket": "reused"})

    consumer.close.assert_awaited_once_with(code=4401)


@pytest.mark.asyncio
async def test_receive_rejects_ticket_subject_mismatch(monkeypatch) -> None:
    consumer = _consumer()
    consumer.scope = {"user": type("User", (), {"pk": 7})()}
    monkeypatch.setattr(
        consumer_module,
        "decode_realtime_ticket",
        lambda _ticket: {"assessment_id": "other", "user_id": "7"},
    )

    await consumer.receive_json({"ticket": "signed", "after_sequence": 3})

    consumer.close.assert_awaited_once_with(code=4403)


@pytest.mark.asyncio
async def test_receive_rejects_invisible_assessment(monkeypatch) -> None:
    consumer = _consumer()
    consumer.scope = {"user": type("User", (), {"pk": 7})()}
    monkeypatch.setattr(
        consumer_module,
        "decode_realtime_ticket",
        lambda _ticket: {"assessment_id": "assessment-realtime", "user_id": "7"},
    )
    consumer._authorized_visibility = AsyncMock(return_value=(None, False))

    await consumer.receive_json({"ticket": "signed", "after_sequence": 3})

    consumer.close.assert_awaited_once_with(code=4403)


@pytest.mark.asyncio
async def test_receive_catches_up_from_cursor_and_does_not_start_watcher_for_terminal_run(
    monkeypatch,
) -> None:
    consumer = _consumer()
    consumer.scope = {"user": type("User", (), {"pk": 7})()}
    monkeypatch.setattr(
        consumer_module,
        "decode_realtime_ticket",
        lambda _ticket: {"assessment_id": "assessment-realtime", "user_id": "7"},
    )
    consumer._authorized_visibility = AsyncMock(return_value=("actor", True))
    consumer._snapshot = AsyncMock(
        return_value={
            "type": "assessment.snapshot",
            "assessment_id": "assessment-realtime",
            "last_sequence": 8,
            "terminal": True,
            "activity_tree": _tree("assessment-realtime", 8, "completed"),
        }
    )

    await consumer.receive_json({"ticket": "signed", "after_sequence": 7})

    assert consumer.assessment_id == "assessment-realtime"
    assert consumer.cursor == 8
    consumer._snapshot.assert_awaited_once_with(after_sequence=7)
    consumer.send_json.assert_awaited_once()
    assert consumer._watch_task is None


@pytest.mark.asyncio
async def test_receive_normalizes_invalid_cursor_and_starts_live_watcher(monkeypatch) -> None:
    consumer = _consumer()
    consumer.scope = {"user": type("User", (), {"pk": 7})()}
    monkeypatch.setattr(
        consumer_module,
        "decode_realtime_ticket",
        lambda _ticket: {"assessment_id": "assessment-realtime", "user_id": "7"},
    )
    consumer._authorized_visibility = AsyncMock(return_value=("actor", True))
    consumer._snapshot = AsyncMock(
        return_value={
            "type": "assessment.snapshot",
            "assessment_id": "assessment-realtime",
            "last_sequence": 4,
            "terminal": False,
            "activity_tree": _tree("assessment-realtime", 4),
        }
    )
    consumer._watch_persisted_activity = AsyncMock()

    await consumer.receive_json({"ticket": "signed", "after_sequence": "not-an-integer"})
    await asyncio.sleep(0)

    assert consumer.cursor == 4
    assert consumer._watch_task is not None
    consumer._watch_task.cancel()
    await asyncio.gather(consumer._watch_task, return_exceptions=True)
    consumer._watch_task = None


@pytest.mark.asyncio
async def test_watcher_emits_only_new_sequences_then_terminal(monkeypatch) -> None:
    consumer = _consumer()
    consumer.cursor = 4
    snapshots = iter(
        [
            {
                "type": "assessment.snapshot",
                "assessment_id": "assessment-realtime",
                "last_sequence": 4,
                "terminal": False,
                "activity_tree": _tree("assessment-realtime", 4),
            },
            {
                "type": "assessment.snapshot",
                "assessment_id": "assessment-realtime",
                "last_sequence": 5,
                "terminal": False,
                "activity_tree": _tree("assessment-realtime", 5),
            },
            {
                "type": "assessment.snapshot",
                "assessment_id": "assessment-realtime",
                "last_sequence": 5,
                "terminal": True,
                "activity_tree": _tree("assessment-realtime", 5, "completed"),
            },
        ]
    )
    consumer._snapshot = AsyncMock(side_effect=lambda after_sequence: next(snapshots))
    consumer.send_json = AsyncMock()
    sleep_calls = 0

    async def no_sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1

    monkeypatch.setattr(consumer_module.asyncio, "sleep", no_sleep)
    consumer.assessment_id = "assessment-realtime"

    await consumer._watch_persisted_activity()

    assert sleep_calls == 3
    assert consumer.send_json.await_count == 2
    assert consumer.send_json.await_args_list[0].args[0]["last_sequence"] == 5
    assert consumer.send_json.await_args_list[1].args[0]["terminal"] is True
    assert consumer.cursor == 5


@pytest.mark.asyncio
async def test_watcher_stops_on_durable_read_error(monkeypatch) -> None:
    consumer = _consumer()
    consumer.assessment_id = "assessment-realtime"
    consumer._snapshot = AsyncMock(side_effect=OSError("temporary store outage"))
    monkeypatch.setattr(consumer_module.asyncio, "sleep", AsyncMock())

    await consumer._watch_persisted_activity()

    consumer.send_json.assert_not_awaited()


@pytest.mark.asyncio
async def test_disconnect_cancels_watcher_and_clears_assessment() -> None:
    consumer = _consumer()
    consumer.assessment_id = "assessment-realtime"
    stopped = asyncio.Event()

    async def sleeper() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    consumer._watch_task = asyncio.create_task(sleeper())
    await asyncio.sleep(0)
    await consumer.disconnect(1000)

    assert consumer.assessment_id == ""
    assert consumer._watch_task is None
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_reconnect_starts_from_last_persisted_cursor_and_keeps_task_identity(
    monkeypatch,
) -> None:
    first = _consumer()
    first.scope = {"user": type("User", (), {"pk": 7})()}
    monkeypatch.setattr(
        consumer_module,
        "decode_realtime_ticket",
        lambda _ticket: {"assessment_id": "assessment-realtime", "user_id": "7"},
    )
    first._authorized_visibility = AsyncMock(return_value=("actor", True))
    first._snapshot = AsyncMock(
        return_value={
            "type": "assessment.snapshot",
            "assessment_id": "assessment-realtime",
            "last_sequence": 12,
            "terminal": False,
            "activity_tree": _tree("assessment-realtime", 12),
        }
    )
    first._watch_persisted_activity = AsyncMock()

    await first.receive_json({"ticket": "signed", "after_sequence": 11})
    await asyncio.sleep(0)
    first._watch_task.cancel()
    await asyncio.gather(first._watch_task, return_exceptions=True)

    second = _consumer()
    second.scope = {"user": type("User", (), {"pk": 7})()}
    second._authorized_visibility = AsyncMock(return_value=("actor", True))
    second._snapshot = AsyncMock(
        return_value={
            "type": "assessment.snapshot",
            "assessment_id": "assessment-realtime",
            "last_sequence": 14,
            "terminal": True,
            "activity_tree": _tree("assessment-realtime", 14, "completed"),
        }
    )

    await second.receive_json({"ticket": "signed", "after_sequence": 12})

    second._snapshot.assert_awaited_once_with(after_sequence=12)
    assert second.cursor == 14
    sent = second.send_json.await_args.args[0]
    assert sent["activity_tree"]["task_id"] == "assessment-realtime"
    assert sent["last_sequence"] == 14


@pytest.mark.asyncio
async def test_snapshot_exposes_shared_state_and_terminal_fallback(monkeypatch):
    consumer = _consumer(assessment_id="assessment-realtime")
    consumer._payload = AsyncMock(
        return_value={
            "events": [],
            "last_sequence": 9,
            "task_state": "failed",
            "run_state": "failed",
            "active_summary": "The assessment failed closed.",
            "approval_state": "approved",
            "execution_state": "failed",
            "workflow_state": "failed",
            "execution_enabled": False,
            "execution_blocking_reason": "The worker was unavailable.",
            "readiness": {"verified": False},
            "evaluation_result": None,
            "updated_at": "2026-08-19T12:00:00+00:00",
            "terminal": True,
            "activity_tree": None,
        }
    )

    snapshot = await consumer._snapshot(after_sequence=8)

    assert snapshot["task_state"] == "failed"
    assert snapshot["active_summary"] == "The assessment failed closed."
    assert snapshot["execution_blocking_reason"] == "The worker was unavailable."
    assert snapshot["terminal"] is True
    assert snapshot["activity_tree"]["status"] == "failed"
    assert snapshot["activity_tree"]["last_sequence"] == 9
