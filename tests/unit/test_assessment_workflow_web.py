from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from test_assessment_workflow import TARGET, _bind, _record, _service

from vulnhunter.agent.store import AgentStore
from vulnhunter.web import operations_views, views


def _configure(settings, tmp_path: Path, service) -> None:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(service.authorization_store.path)
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.db")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.VULNHUNTER_NUCLEI_PROFILE_CONFIG = str(service.profile_config)
    settings.VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST = str(service.template_manifest_path)
    settings.VULNHUNTER_NUCLEI_TEMPLATE_ROOT = str(service.template_root)
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = str(service.evidence_root)
    settings.VULNHUNTER_NUCLEI_READINESS_REPORT = str(service.readiness_report)


def _actor():
    return SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="operator-a"),
    )


@pytest.mark.django_db
def test_authorization_endpoint_requires_authentication(client, settings, tmp_path):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)

    response = client.get("/scans/authorizations/")

    assert response.status_code == 302
    assert "/login/" in response["Location"]


@pytest.mark.django_db
def test_authorization_endpoint_returns_only_minimum_active_actor_fields(
    client, settings, tmp_path
):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)
    record = _record(service.authorization_store)
    _bind(service, record)
    user = get_user_model().objects.create_user(username="web-a", password="password-1234")
    client.force_login(user)

    with (
        patch.object(operations_views, "authorized_actor", return_value=_actor()),
        patch.object(
            operations_views.AssessmentWorkflowService,
            "from_settings",
            return_value=service,
        ),
    ):
        response = client.get("/scans/authorizations/")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "private, no-store, max-age=0"
    payload = response.json()["authorizations"]
    assert len(payload) == 1
    assert set(payload[0]) == {
        "authorization_id",
        "display_label",
        "expires_at",
        "approved_targets",
        "approved_protocols",
        "approved_ports",
        "approved_profiles",
    }


@pytest.mark.django_db
def test_browser_modified_target_and_profile_are_rejected_by_post(client, settings, tmp_path):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)
    record = _record(service.authorization_store)
    _bind(service, record)
    user = get_user_model().objects.create_user(username="web-a", password="password-1234")
    client.force_login(user)

    with (
        patch.object(operations_views, "authorized_actor", return_value=_actor()),
        patch.object(
            operations_views.AssessmentWorkflowService,
            "from_settings",
            return_value=service,
        ),
    ):
        target_response = client.post(
            "/scans/new/",
            {
                "authorization_id": record.authorization_id,
                "target": "https://other.lab:443/app",
                "protocol": "https",
                "port": "443",
                "profile": "passive",
            },
        )
        profile_response = client.post(
            "/scans/new/",
            {
                "authorization_id": record.authorization_id,
                "target": TARGET,
                "protocol": "https",
                "port": "443",
                "profile": "intrusive",
            },
        )

    assert target_response.status_code == 200
    assert b"target is not exactly authorized" in target_response.content
    assert profile_response.status_code == 200
    assert b"profile is not authorized" in profile_response.content
    assert AgentStore(tmp_path / "agent.db").list_tasks() == ()


@pytest.mark.django_db
def test_assessment_creation_post_requires_csrf(settings, tmp_path):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)
    user = get_user_model().objects.create_user(username="csrf-a", password="password-1234")
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)

    response = client.post("/scans/new/", {})

    assert response.status_code == 403


@pytest.mark.django_db
def test_empty_state_and_modal_are_real_query_backed(client, settings, tmp_path):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)
    user = get_user_model().objects.create_user(username="web-a", password="password-1234")
    client.force_login(user)

    with patch.object(views, "_protected", return_value=_actor()):
        response = client.get("/scans/")

    content = response.content.decode("utf-8")
    assert response.status_code == 200
    assert "No Active Assessment" in content
    assert "data-assessment-open" in content
    assert '<select name="target"' in content
    assert '<input name="target"' not in content
    assert "worker-readiness checks are required before queueing" in content
