from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from test_web_app import _bootstrap_identity, _mapped_user

from vulnhunter.agent.store import AgentStore
from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import intelligence_status, navigation_for


@pytest.fixture
def web_paths(tmp_path: Path, settings) -> Path:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(tmp_path / "auth.db")
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.sqlite3")
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.VULNHUNTER_PILOT_PLAN_ROOT = str(Path("config/pilot").resolve())
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    return tmp_path


@pytest.mark.django_db
def test_navigation_exposes_real_workspaces_and_highlights_every_detail_route(
    web_paths,
) -> None:
    user = get_user_model().objects.create_user(username="navigation-audit")
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="admin-a",
        product_roles=[
            "system-administrator",
            "campaign-operator",
            "campaign-approver",
            "reviewer",
            "adjudicator",
            "security-auditor",
            "model-analyst",
        ],
    )
    entries = {str(item["label"]): item for item in navigation_for(user)}
    assert "Approval Centre" in entries
    assert "Mobile Analysis" in entries
    assert "web-finding-detail" in entries["Findings"]["active_routes"]
    assert "web-review-detail" in entries["Review Queue"]["active_routes"]
    assert "web-adjudication-detail" in entries["Adjudications"]["active_routes"]
    assert "web-release-detail" in entries["Releases"]["active_routes"]
    assert "web-dataset-detail" in entries["Datasets"]["active_routes"]
    assert "web-model-detail" in entries["Models"]["active_routes"]
    assert "web-pilot-plan-download" in entries["Reports"]["active_routes"]
    assert "web-mobile-analysis" not in entries["Settings"]["active_routes"]


@pytest.mark.django_db
def test_settings_page_renders_real_posture_without_exposing_secret_paths(
    client,
    web_paths,
    settings,
) -> None:
    _bootstrap_identity(web_paths)
    AgentStore.initialize_database(web_paths / "agent.db")
    user = _mapped_user(
        username="settings-audit",
        password="password-1234",
        product_roles=["system-administrator", "security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    response = client.get("/settings/")
    assert response.status_code == 200
    for marker in (
        b"Settings &amp; readiness",
        b"Operator identity",
        b"Activation gates",
        b"Core capability health",
        b"Browser security posture",
    ):
        assert marker in response.content
    assert b"Configuration workspaces" not in response.content
    assert str(Path(settings.VULNHUNTER_GROQ_API_KEY_FILE)).encode() not in response.content
    assert b"password-1234" not in response.content
    assert b"Traceback" not in response.content


@pytest.mark.django_db
def test_pilot_report_downloads_use_existing_safe_exporter(
    client,
    web_paths,
) -> None:
    _bootstrap_identity(web_paths)
    user = _mapped_user(
        username="report-audit",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    plan = SimpleNamespace(
        title="Local pilot",
        model_dump=lambda mode: {"plan_id": "local-pilot", "title": "Local pilot"},
    )
    report = SimpleNamespace(
        plan_sha256="a" * 64,
        report_sha256="b" * 64,
        model_dump=lambda mode: {"valid": True, "plan_sha256": "a" * 64},
    )
    record = SimpleNamespace(plan_id="local-pilot", plan=plan, report=report)
    with patch(
        "vulnhunter.web.report_views.get_pilot_plan_record",
        return_value=record,
    ):
        json_response = client.get("/reports/plans/local-pilot/download/json/")
        html_response = client.get("/reports/plans/local-pilot/download/html/")
    assert json_response.status_code == 200
    assert json_response["Content-Type"].startswith("application/json")
    assert "attachment" in json_response["Content-Disposition"]
    assert len(json_response["X-VulnHunter-Artifact-SHA256"]) == 64
    assert b'"plan_id": "local-pilot"' in json_response.content
    assert html_response.status_code == 200
    assert html_response["Content-Type"].startswith("text/html")
    assert b"VulnHunter pilot plan" in html_response.content
    assert client.get("/reports/plans/local-pilot/download/pdf/").status_code == 404


def test_graphify_status_honours_explicit_execution_flag(settings) -> None:
    settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED = True
    settings.VULNHUNTER_GROQ_ENABLED = False
    observed: dict[str, object] = {}

    class FakeGraphify:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        def load_artifact(self, path, *, repository_root):
            return SimpleNamespace(graph_sha256="c" * 64, nodes=())

    with patch("vulnhunter.web.services.GraphifyAdapter", FakeGraphify):
        rows = intelligence_status()
    assert observed["execution_enabled"] is True
    assert rows[0]["state"] == "READY_ENABLED"


def test_browser_audit_configuration_has_no_stale_routes() -> None:
    script = Path(".playwright-validate.cjs").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/quality.yml").read_text(encoding="utf-8")
    assert "/oracle/" not in script
    assert "ui-reference-run" not in script
    assert "VULNHUNTER_UI_MANIFEST" in script
    assert "overflowX" in script
    assert "unnamedControls" in script
    assert "playwright@1.55.0" in workflow
    assert "Browser UI audit" in workflow
