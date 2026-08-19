from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse


@pytest.mark.django_db
def test_mobile_source_hunt_handoff_persists_report_and_returns_authoritative_payload():
    user = get_user_model().objects.create_user(
        username="source-hunt-view", password="password-1234"
    )
    client = Client()
    client.force_login(user)
    plan = {"execution": {"state": "completed"}, "run_id": "apk-run"}
    report = {
        "report_id": "source-mobile-report-1234567890abcdef12345678",
        "state": "completed",
        "results": [],
        "graph": {"nodes": [], "edges": []},
    }
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-view"))
    projection = {"assessment_id": "apk-run", "task_card": {"assessment_id": "apk-run"}}
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
    )
    remember.assert_called_once()
    assert plan["source_hunt"]["report"] == report
