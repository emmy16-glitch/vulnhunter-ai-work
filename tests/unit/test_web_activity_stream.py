from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web import stream_views

ROOT = Path(__file__).resolve().parents[2]
ACTIVITY_SCRIPT = ROOT / "vulnhunter" / "web" / "static" / "web" / "activity.js"
APP_SCRIPT = ROOT / "vulnhunter" / "web" / "static" / "web" / "app.js"
URLS = ROOT / "vulnhunter" / "web" / "urls.py"


def test_assessment_ui_uses_sse_instead_of_browser_timers() -> None:
    activity = ACTIVITY_SCRIPT.read_text(encoding="utf-8")
    app = APP_SCRIPT.read_text(encoding="utf-8")
    urls = URLS.read_text(encoding="utf-8")

    assert "new EventSource" in activity
    assert "activity/stream/" in urls
    assert "web-agent-run-activity-stream" in urls
    assert "setTimeout(poll" not in activity
    assert "setInterval" not in app


@pytest.mark.django_db
def test_activity_stream_requires_authentication(client, settings) -> None:
    settings.ALLOWED_HOSTS = ["testserver"]

    response = client.get("/agent/runs/run-stream/activity/stream/")

    assert response.status_code == 302
    assert "/login/" in response["Location"]


@pytest.mark.django_db
def test_activity_stream_returns_backend_snapshot(client, settings, monkeypatch) -> None:
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="stream-operator",
        password="password-1234",
    )
    client.force_login(user)

    created_at = datetime.now(UTC) - timedelta(seconds=93)
    updated_at = datetime.now(UTC)
    run = SimpleNamespace(
        run_id="run-stream",
        current_state="running",
        approval_state=SimpleNamespace(value="pending"),
        execution_state="tool_planned",
        evaluation_result=None,
        created_at=created_at,
        updated_at=updated_at,
    )
    monkeypatch.setattr(stream_views, "authorized_actor", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        stream_views,
        "product_service",
        lambda: SimpleNamespace(get_agent_run=lambda _run_id: run),
    )
    monkeypatch.setattr(
        stream_views,
        "activity_payload",
        lambda _run_id, *, after_sequence: {
            "events": [
                {
                    "sequence": after_sequence + 1,
                    "event_id": "event-stream-5",
                    "timestamp": updated_at.isoformat(),
                    "event_type": "tool_planned",
                    "summary": "Nuclei plan is awaiting approval.",
                    "run_state": "running",
                    "audit_reference": "audit-stream-5",
                    "metadata": {"tool_id": "nuclei"},
                }
            ],
            "last_sequence": after_sequence + 1,
            "run_state": "running",
            "terminal": False,
        },
    )

    response = client.get(
        "/agent/runs/run-stream/activity/stream/",
        {"after_sequence": "4"},
    )
    body = b"".join(response.streaming_content).decode("utf-8")

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/event-stream")
    assert response["X-Accel-Buffering"] == "no"
    assert "event: activity" in body
    assert "id: 5" in body

    data_line = next(line for line in body.splitlines() if line.startswith("data: "))
    payload = json.loads(data_line.removeprefix("data: "))
    assert payload["run_id"] == "run-stream"
    assert payload["approval_state"] == "pending"
    assert payload["execution_state"] == "tool_planned"
    assert payload["elapsed_seconds"] >= 93
    assert payload["events"][0]["metadata"] == {"tool_id": "nuclei"}


@pytest.mark.django_db
def test_activity_stream_rejects_invalid_sequence(client, settings, monkeypatch) -> None:
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="stream-invalid",
        password="password-1234",
    )
    client.force_login(user)
    monkeypatch.setattr(stream_views, "authorized_actor", lambda *_args, **_kwargs: object())

    response = client.get(
        "/agent/runs/run-stream/activity/stream/",
        {"after_sequence": "not-an-integer"},
    )

    assert response.status_code == 400
    assert "must be integers" in response.json()["detail"]
