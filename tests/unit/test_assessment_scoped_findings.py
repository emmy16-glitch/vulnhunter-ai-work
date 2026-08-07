from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web.conversational_views import _SESSION_STATE
from vulnhunter.web.findings_views import _CONVERSATION_STATE_SESSION_KEY


def _summary(run_id: str) -> SimpleNamespace:
    return SimpleNamespace(run_id=run_id)


def _detail(run_id: str, title: str) -> SimpleNamespace:
    return SimpleNamespace(
        run_id=run_id,
        objective=f"Assessment {run_id}",
        requested_tool="nuclei",
        current_state="completed",
        updated_at=datetime(2026, 8, 7, 12, 0, tzinfo=UTC),
        findings=(
            {
                "evidence_id": f"evidence-{run_id}",
                "title": title,
                "severity": "medium",
                "confidence": "high",
                "verification": "candidate",
                "target_reference": "private lab target",
            },
        ),
    )


def _service() -> SimpleNamespace:
    details = {
        "run-one": _detail("run-one", "Finding from assessment one"),
        "run-two": _detail("run-two", "Finding from assessment two"),
    }
    return SimpleNamespace(
        list_agent_runs=lambda: (_summary("run-one"), _summary("run-two")),
        get_agent_run=lambda run_id: details[str(run_id)],
    )


def _login(client) -> None:
    user = get_user_model().objects.create_user(
        username="assessment-findings-user",
        password="password-1234",
    )
    client.force_login(user)


def _select(client, run_id: str) -> None:
    session = client.session
    session[_SESSION_STATE] = {"run_id": run_id}
    session.save()


@pytest.mark.django_db
def test_findings_defaults_to_server_selected_assessment(client) -> None:
    _login(client)
    _select(client, "run-one")

    with (
        patch("vulnhunter.web.findings_views.authorized_actor", return_value=object()),
        patch("vulnhunter.web.findings_views.product_service", return_value=_service()),
        patch("vulnhunter.web.findings_views.run_readable_to_actor", return_value=True),
    ):
        response = client.get("/findings/")

    assert response.status_code == 200
    assert b"Finding from assessment one" in response.content
    assert b"Finding from assessment two" not in response.content
    assert b"Selected assessment findings" in response.content
    assert b"View all account findings" in response.content


@pytest.mark.django_db
def test_explicit_assessment_deep_link_overrides_previous_session_selection(client) -> None:
    _login(client)
    _select(client, "run-one")

    with (
        patch("vulnhunter.web.findings_views.authorized_actor", return_value=object()),
        patch("vulnhunter.web.findings_views.product_service", return_value=_service()),
        patch("vulnhunter.web.findings_views.run_readable_to_actor", return_value=True),
    ):
        response = client.get("/findings/?assessment=run-two")

    assert response.status_code == 200
    assert b"Finding from assessment two" in response.content
    assert b"Finding from assessment one" not in response.content


@pytest.mark.django_db
def test_explicit_global_scope_keeps_deliberate_account_wide_findings_available(client) -> None:
    _login(client)
    _select(client, "run-one")

    with (
        patch("vulnhunter.web.findings_views.authorized_actor", return_value=object()),
        patch("vulnhunter.web.findings_views.product_service", return_value=_service()),
        patch("vulnhunter.web.findings_views.run_readable_to_actor", return_value=True),
    ):
        response = client.get("/findings/?scope=all")

    assert response.status_code == 200
    assert b"Finding from assessment one" in response.content
    assert b"Finding from assessment two" in response.content
    assert b"View all account findings" not in response.content


@pytest.mark.django_db
def test_selected_findings_preserve_private_not_found_for_unreadable_assessment(client) -> None:
    _login(client)
    _select(client, "run-two")

    def readable(summary, _actor):
        return str(summary.run_id) == "run-one"

    with (
        patch("vulnhunter.web.findings_views.authorized_actor", return_value=object()),
        patch("vulnhunter.web.findings_views.product_service", return_value=_service()),
        patch("vulnhunter.web.findings_views.run_readable_to_actor", side_effect=readable),
    ):
        response = client.get("/findings/")

    assert response.status_code == 404
    assert b"Finding from assessment two" not in response.content


def test_findings_and_conversation_share_one_server_selected_assessment_session_key() -> None:
    assert _CONVERSATION_STATE_SESSION_KEY == _SESSION_STATE
