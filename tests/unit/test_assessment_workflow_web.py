from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from test_assessment_workflow import _service

from vulnhunter.agent.store import AgentStore
from vulnhunter.web import views


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
def test_retired_authorization_choices_endpoint_returns_not_found(client, settings, tmp_path):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)
    user = get_user_model().objects.create_user(
        username="retired-authorization-route",
        password="password-1234",
    )
    client.force_login(user)

    with patch.object(views, "_protected", return_value=_actor()):
        response = client.get("/scans/authorizations/")

    assert response.status_code == 404


@pytest.mark.django_db
def test_retired_assessment_creation_post_fails_closed_without_csrf(settings, tmp_path):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)
    user = get_user_model().objects.create_user(username="csrf-a", password="password-1234")
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)

    response = client.post("/scans/new/", {})

    assert response.status_code == 403
    assert AgentStore(tmp_path / "agent.db").list_tasks() == ()


@pytest.mark.django_db
def test_assessment_history_is_workspace_led_without_a_second_creation_modal(
    client, settings, tmp_path
):
    service = _service(tmp_path)
    _configure(settings, tmp_path, service)
    user = get_user_model().objects.create_user(username="web-a", password="password-1234")
    client.force_login(user)

    with patch.object(views, "_protected", return_value=_actor()):
        response = client.get("/scans/")

    content = response.content.decode("utf-8")
    assert response.status_code == 200
    assert "Assessment History" in content
    assert "No assessments yet" in content
    assert "Open workspace" in content
    assert "data-assessment-open" not in content
    assert '<select name="target"' not in content
    assert "New Assessment" not in content
