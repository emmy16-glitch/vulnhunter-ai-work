from __future__ import annotations

from types import SimpleNamespace

from vulnhunter.web import conversational_views
from vulnhunter.web.conversation_state import contextual_chat_reply


def test_ordinary_chat_is_not_replaced_by_completed_run_status() -> None:
    payload = {
        "target": "http://10.0.11.34:8010/",
        "current_step": "Analysis complete.",
        "approval": None,
    }

    reply = contextual_chat_reply(
        "What can you do?",
        payload,
        "I can prepare and explain a new authorised assessment.",
    )

    assert reply == "I can prepare and explain a new authorised assessment."
    assert "tracking the current assessment" not in reply.casefold()


def test_new_conversation_does_not_attach_latest_completed_run(monkeypatch) -> None:
    latest = SimpleNamespace(run_id="old-completed-run")
    monkeypatch.setattr(
        conversational_views,
        "_latest_visible_run",
        lambda actor, target=None: latest,
    )

    assert conversational_views._authoritative_run({}, object()) is None
    assert (
        conversational_views._authoritative_run(
            {},
            object(),
            target="http://10.0.1.51:8010/",
        )
        is latest
    )


def test_explicit_session_run_remains_authoritative(monkeypatch) -> None:
    selected = SimpleNamespace(
        run_id="selected-run",
        scope_summary="http://10.0.1.51:8010/",
        objective="",
    )
    monkeypatch.setattr(conversational_views, "_visible_run", lambda run_id, actor: selected)

    resolved = conversational_views._authoritative_run(
        {"run_id": "selected-run"},
        object(),
    )

    assert resolved is selected
