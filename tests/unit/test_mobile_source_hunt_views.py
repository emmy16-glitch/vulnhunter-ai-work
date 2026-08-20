from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse


@pytest.fixture
def source_hunt_client(db):
    user = get_user_model().objects.create_user(
        username="source-hunt-view", password="password-1234"
    )
    client = Client()
    client.force_login(user)
    return client


def _actor():
    return SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-view"))


def _projection():
    return {"assessment_id": "apk-run", "task_card": {"assessment_id": "apk-run"}}


def _report():
    return {
        "report_id": "source-mobile-report-1234567890abcdef12345678",
        "state": "completed",
        "results": [],
        "graph": {"nodes": [], "edges": []},
    }


@pytest.mark.django_db
def test_mobile_source_hunt_handoff_persists_report_and_returns_authoritative_payload():
    user = get_user_model().objects.create_user(
        username="source-hunt-view-single", password="password-1234"
    )
    client = Client()
    client.force_login(user)
    plan = {"execution": {"state": "completed"}, "run_id": "apk-run"}
    report = _report()
    actor = _actor()
    projection = _projection()
    message = {"role": "assistant", "kind": "source_hunt", "content": "persisted"}

    with (
        patch("vulnhunter.web.mobile_source_hunt_views._actor", return_value=actor),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.current_mobile_plan",
            return_value=plan,
        ) as current_plan,
        patch(
            "vulnhunter.web.mobile_source_hunt_views.run_mobile_source_hunt_handoff",
            return_value={
                "report": report,
                "report_path": "/tmp/source-hunt-report.json",
                "selected_seed_id": "seed-1",
            },
        ) as run_handoff,
        patch("vulnhunter.web.mobile_source_hunt_views.remember_mobile_plan") as remember,
        patch(
            "vulnhunter.web.mobile_source_hunt_views.mobile_assessment_projection",
            return_value=projection,
        ),
        patch(
            "vulnhunter.web.mobile_source_hunt_views._append_message",
            return_value=message,
        ),
    ):
        response = client.post(
            reverse("web-conversation-mobile-source-hunt"),
            {"seed_id": "seed-1"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["assessment_projection"] == projection
    assert payload["task_card"] == projection["task_card"]
    assert payload["message"] == message
    assert payload["source_hunt"] == report
    current_plan.assert_called_once_with(
        response.wsgi_request,
        requested_by="reviewer-view",
    )
    run_handoff.assert_called_once_with(
        plan=plan,
        requested_by="reviewer-view",
        selected_seed_id="seed-1",
        selected_record_id=None,
        selected_seed_ids=(),
        selected_record_ids=(),
    )
    remember.assert_called_once()
    assert plan["source_hunt"]["report"] == report


@pytest.mark.django_db
def test_mobile_source_hunt_accepts_bulk_seed_ids(source_hunt_client):
    with (
        patch("vulnhunter.web.mobile_source_hunt_views._actor", return_value=_actor()),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.current_mobile_plan",
            return_value={"execution": {"state": "completed"}},
        ),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.run_mobile_source_hunt_handoff",
            return_value={"report": _report(), "report_path": "/tmp/report.json"},
        ) as run_handoff,
        patch("vulnhunter.web.mobile_source_hunt_views.remember_mobile_plan"),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.mobile_assessment_projection",
            return_value=_projection(),
        ),
        patch(
            "vulnhunter.web.mobile_source_hunt_views._append_message",
            return_value={"content": "persisted"},
        ),
    ):
        response = source_hunt_client.post(
            reverse("web-conversation-mobile-source-hunt"),
            {"seed_ids": '["seed-1", "seed-2", "seed-1"]'},
        )

    assert response.status_code == 200
    assert run_handoff.call_args.kwargs["selected_seed_ids"] == ("seed-1", "seed-2")
    assert run_handoff.call_args.kwargs["selected_record_ids"] == ()


@pytest.mark.django_db
def test_mobile_source_hunt_accepts_bulk_record_ids(source_hunt_client):
    with (
        patch("vulnhunter.web.mobile_source_hunt_views._actor", return_value=_actor()),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.current_mobile_plan",
            return_value={"execution": {"state": "completed"}},
        ),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.run_mobile_source_hunt_handoff",
            return_value={"report": _report(), "report_path": "/tmp/report.json"},
        ) as run_handoff,
        patch("vulnhunter.web.mobile_source_hunt_views.remember_mobile_plan"),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.mobile_assessment_projection",
            return_value=_projection(),
        ),
        patch(
            "vulnhunter.web.mobile_source_hunt_views._append_message",
            return_value={"content": "persisted"},
        ),
    ):
        response = source_hunt_client.post(
            reverse("web-conversation-mobile-source-hunt"),
            {"record_ids": '["record-1", "record-2"]'},
        )

    assert response.status_code == 200
    assert run_handoff.call_args.kwargs["selected_record_ids"] == ("record-1", "record-2")
    assert run_handoff.call_args.kwargs["selected_seed_ids"] == ()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "payload",
    [
        {"record_ids": "not-json"},
        {"seed_ids": "[" + ",".join(f'"seed-{index}"' for index in range(65)) + "]"},
    ],
)
def test_mobile_source_hunt_rejects_invalid_or_oversized_bulk_selection(
    source_hunt_client, payload
):
    with (
        patch("vulnhunter.web.mobile_source_hunt_views._actor", return_value=_actor()),
        patch(
            "vulnhunter.web.mobile_source_hunt_views.current_mobile_plan",
            return_value={"execution": {"state": "completed"}},
        ),
    ):
        response = source_hunt_client.post(
            reverse("web-conversation-mobile-source-hunt"),
            payload,
        )

    assert response.status_code == 400
    assert "Source Hunt selections" in response.json()["detail"]
