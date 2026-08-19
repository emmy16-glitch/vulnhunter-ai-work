from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from vulnhunter.api import views


@pytest.fixture
def api_user(db):
    return get_user_model().objects.create_user(
        username="api-user",
        password="long-api-password-1234",
    )


@pytest.fixture
def api_actor():
    return SimpleNamespace(
        product_roles=("campaign-operator",),
        governance_identity=SimpleNamespace(reviewer_id="api-user"),
    )


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


@pytest.mark.django_db
def test_api_v1_requires_authentication(api_user):
    assert _client().get("/api/v1/me/").status_code == 403
    assert _client(api_user).get("/api/v1/me/").status_code == 403


@pytest.mark.django_db
def test_api_v1_me_and_readiness_use_authoritative_actor(monkeypatch, api_user, api_actor):
    monkeypatch.setattr(views, "authorized_actor", lambda *_args, **_kwargs: api_actor)
    monkeypatch.setattr(
        views,
        "deployment_readiness",
        lambda: SimpleNamespace(
            ready=True,
            as_payload=lambda: {"status": "ready", "checks": {"database": "ok"}},
        ),
    )
    client = _client(api_user)

    me = client.get("/api/v1/me/")
    readiness = client.get("/api/v1/readiness/")

    assert me.status_code == 200
    assert me.json() == {
        "id": str(api_user.pk),
        "username": "api-user",
        "roles": ["campaign-operator"],
        "reviewer_id": "api-user",
    }
    assert readiness.status_code == 200
    assert readiness.json()["status"] == "ready"


@pytest.mark.django_db
def test_api_v1_assessment_events_are_cursor_based_and_object_scoped(
    monkeypatch,
    api_user,
    api_actor,
):
    run = SimpleNamespace(run_id="assessment-api-01")
    monkeypatch.setattr(views, "authorized_actor", lambda *_args, **_kwargs: api_actor)
    monkeypatch.setattr(views, "_visible_run", lambda *_args, **_kwargs: run)
    monkeypatch.setattr(
        views,
        "_conversation_stream_payload",
        lambda _run, *, after_sequence: {
            "events": [{"sequence": after_sequence + 1, "type": "tool.started"}],
            "last_sequence": after_sequence + 1,
            "run_state": "executing",
            "terminal": False,
        },
    )

    response = _client(api_user).get(
        "/api/v1/assessments/assessment-api-01/events/?after_sequence=7"
    )

    assert response.status_code == 200
    assert response.json() == {
        "assessment_id": "assessment-api-01",
        "events": [{"sequence": 8, "type": "tool.started"}],
        "last_sequence": 8,
        "run_state": "executing",
        "terminal": False,
        "activity_tree": {
            "schema_version": "1.0",
            "task_id": "assessment-api-01",
            "status": "running",
            "last_sequence": 8,
            "nodes": [],
        },
    }
    invalid = _client(api_user).get(
        "/api/v1/assessments/assessment-api-01/events/?after_sequence=-1"
    )
    assert invalid.status_code == 400


@pytest.mark.django_db
def test_api_v1_realtime_ticket_is_bound_to_assessment_and_expires(
    monkeypatch,
    api_user,
    api_actor,
):
    run = SimpleNamespace(run_id="assessment-api-ticket")
    monkeypatch.setattr(views, "authorized_actor", lambda *_args, **_kwargs: api_actor)
    monkeypatch.setattr(views, "_visible_run", lambda *_args, **_kwargs: run)

    response = _client(api_user).post(
        "/api/v1/realtime/ticket/",
        {"assessment_id": "assessment-api-ticket"},
        format="json",
    )

    assert response.status_code == 201
    payload = response.json()
    decoded = views.decode_realtime_ticket(payload["ticket"])
    assert decoded["assessment_id"] == "assessment-api-ticket"
    assert decoded["user_id"] == str(api_user.pk)
    assert payload["expires_in"] == 60


@pytest.mark.django_db
def test_api_v1_ticket_does_not_expose_unknown_assessment(monkeypatch, api_user, api_actor):
    from django.http import Http404

    monkeypatch.setattr(views, "authorized_actor", lambda *_args, **_kwargs: api_actor)
    monkeypatch.setattr(
        views,
        "_visible_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(Http404()),
    )

    response = _client(api_user).post(
        "/api/v1/realtime/ticket/",
        {"assessment_id": "missing"},
        format="json",
    )

    assert response.status_code == 404
