from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web import conversational_views


@pytest.mark.django_db
def test_conversation_activity_stream_requires_authentication(client, settings) -> None:
    settings.ALLOWED_HOSTS = ["testserver"]

    response = client.get("/workspace/runs/run-conversation/activity/stream/")

    assert response.status_code == 302
    assert "/login/" in response["Location"]


@pytest.mark.django_db
def test_conversation_activity_stream_returns_incremental_snapshot(
    client, settings, monkeypatch
) -> None:
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="conversation-stream-operator",
        password="password-1234",
    )
    client.force_login(user)

    created_at = datetime.now(UTC) - timedelta(seconds=12)
    updated_at = datetime.now(UTC)
    run = SimpleNamespace(
        run_id="run-conversation",
        current_state="running",
        workflow_state="running",
        approval_state=SimpleNamespace(value="approved"),
        execution_state="running",
        evaluation_result=None,
        execution_blocking_reason=None,
        created_at=created_at,
        updated_at=updated_at,
    )
    monkeypatch.setattr(
        conversational_views,
        "_actor",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        conversational_views,
        "_visible_run",
        lambda _run_id, _actor: run,
    )
    monkeypatch.setattr(
        conversational_views,
        "_run_payload",
        lambda _run: {
            "run_id": "run-conversation",
            "state": "running",
            "terminal": False,
            "events": [],
            "last_sequence": 4,
            "findings": [],
            "artifacts": [],
        },
    )
    monkeypatch.setattr(
        conversational_views,
        "activity_payload",
        lambda _run_id, *, after_sequence: {
            "events": [
                {
                    "sequence": after_sequence + 1,
                    "event_id": "event-conversation-5",
                    "timestamp": updated_at.isoformat(),
                    "event_type": "tool_started",
                    "summary": "The isolated worker started the approved passive assessment.",
                }
            ],
            "last_sequence": after_sequence + 1,
            "run_state": "running",
            "terminal": False,
        },
    )

    response = client.get(
        "/workspace/runs/run-conversation/activity/stream/",
        {"after_sequence": "4"},
    )
    body = b"".join(response.streaming_content).decode("utf-8")

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/event-stream")
    assert response["Cache-Control"] == "private, no-cache, no-store, must-revalidate"
    assert response["X-Accel-Buffering"] == "no"
    assert "event: activity" in body
    assert "id: 5" in body

    data_line = next(line for line in body.splitlines() if line.startswith("data: "))
    payload = json.loads(data_line.removeprefix("data: "))
    assert payload["run_id"] == "run-conversation"
    assert payload["last_sequence"] == 5
    assert (
        payload["active_summary"]
        == "The isolated worker is processing the approved passive assessment."
    )
    assert payload["events"][0]["event_id"] == "event-conversation-5"


@pytest.mark.django_db
def test_conversation_activity_stream_rejects_invalid_cursor(client, settings, monkeypatch) -> None:
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="conversation-stream-invalid",
        password="password-1234",
    )
    client.force_login(user)
    monkeypatch.setattr(
        conversational_views,
        "_actor",
        lambda *_args, **_kwargs: object(),
    )

    response = client.get(
        "/workspace/runs/run-conversation/activity/stream/",
        {"after_sequence": "not-an-integer"},
    )

    assert response.status_code == 400
    assert "must be integers" in response.json()["detail"]
