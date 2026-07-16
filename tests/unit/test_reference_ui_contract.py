from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "vulnhunter" / "web" / "templates" / "web" / "base.html"
LISTING = ROOT / "vulnhunter" / "web" / "templates" / "web" / "agent_runs.html"
DETAIL = ROOT / "vulnhunter" / "web" / "templates" / "web" / "agent_run_detail.html"
CSS = ROOT / "vulnhunter" / "web" / "static" / "web" / "app.css"
SCRIPT = ROOT / "vulnhunter" / "web" / "static" / "web" / "app.js"
SERVICES = ROOT / "vulnhunter" / "web" / "services.py"
VIEWS = ROOT / "vulnhunter" / "web" / "views.py"
OPERATIONS_VIEWS = ROOT / "vulnhunter" / "web" / "operations_views.py"
URLS = ROOT / "vulnhunter" / "web" / "urls.py"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_approved_navigation_information_architecture_is_present():
    services = _text(SERVICES)
    for section in (
        "Overview",
        "Collection",
        "Analysis",
        "Independent Review",
        "Governance",
        "Intelligence",
        "Assurance",
        "System",
    ):
        assert f'"section_label": "{section}"' in services
    for label in (
        "Dashboard",
        "Authorizations",
        "New Scan",
        "Scan Runs",
        "Findings",
        "Review Queue",
        "Adjudications",
        "Campaigns",
        "Releases",
        "Datasets",
        "Models",
        "Audit",
        "Reports",
        "Settings",
    ):
        assert f'"label": "{label}"' in services


def test_approved_navigation_routes_are_real_and_contextual():
    urls = _text(URLS)
    base = _text(BASE)
    for route_name in (
        "web-authorization-list",
        "web-new-scan",
        "web-scan-run-list",
        "web-review-queue",
        "web-adjudication-queue",
        "web-release-list",
        "web-dataset-list",
        "web-model-list",
        "web-audit-overview",
    ):
        assert route_name in urls
    assert "current_route in item.active_routes" in base
    assert "vh-nav-section-label" in base


def test_blueprint_tokens_and_semantic_colours_are_authoritative():
    css = _text(CSS).lower()
    for token in (
        "--vh-accent: #4f8cff",
        "--vh-accent-hover: #76a6ff",
        "--vh-info: #38bdf8",
        "--vh-success: #22c55e",
        "--vh-warning: #f59e0b",
        "--vh-danger: #ef4444",
    ):
        assert token in css
    assert "background: linear-gradient(90deg, var(--vh-accent), var(--vh-accent-hover))" in css
    assert ".vh-status-live, .vh-status-safe" in css


def test_blueprint_shell_dimensions_and_breakpoints_are_present():
    css = _text(CSS)
    for token in (
        "--vh-sidebar-width: 264px",
        "--vh-header-height: 64px",
        "--vh-content-max-width: 1600px",
        "@media (min-width: 1024px)",
        "@media (max-width: 1023px)",
        "@media (max-width: 639px)",
        "overflow-x: hidden",
    ):
        assert token in css
    assert 'window.matchMedia("(max-width: 1023px)").matches' in _text(SCRIPT)


def test_reference_workspace_remains_interactive_and_truthful():
    listing = _text(LISTING)
    detail = _text(DETAIL)
    script = _text(SCRIPT)
    for token in (
        "vh-workstream-panel",
        "vh-inspector",
        "vh-bottom-dock",
        "vh-stage-disclosure",
        "vh-output-panel",
        "vh-attack-path",
    ):
        assert token in listing + detail
    assert "data-assessment-collection" in listing
    assert "data-launch-dialog" in listing
    assert "data-authorization-select" in listing
    assert detail.count('role="tab"') >= 8
    assert "querySelector(\":scope > [role='tablist']\")" in script
    for fake_value in (
        "acme-payments.com",
        "CVE-2023-50287",
        "/api/v1/users",
        "Nuclei v3.1.3",
    ):
        assert fake_value not in listing + detail


def test_target_profile_and_approval_controls_are_real():
    base = _text(BASE)
    detail = _text(DETAIL)
    operations = _text(OPERATIONS_VIEWS)
    assert '<details class="vh-context-menu">' in base
    assert 'aria-label="Select assessment target"' in base
    assert 'aria-label="Select assessment profile"' in base
    assert "{% if pending_approval %}" in detail
    assert '<dialog id="vh-approval-dialog"' in detail
    assert 'name="decision" value="approve_once"' in detail
    assert 'name="decision" value="deny_continue_safely"' in detail
    assert "url_has_allowed_host_and_scheme" in operations


def test_new_workflow_surfaces_are_read_only_and_data_backed():
    views = _text(VIEWS)
    operations = _text(OPERATIONS_VIEWS)
    for function_name in (
        "authorization_list_view",
        "review_queue_view",
        "adjudication_queue_view",
        "release_list_view",
        "dataset_list_view",
        "model_list_view",
    ):
        assert f"def {function_name}" in views
    assert "def new_scan_view" in operations
    new_scan = _text(ROOT / "vulnhunter" / "web" / "templates" / "web" / "new_scan.html")
    assert "Create launch request" in new_scan
    assert "This form does not start a scanner or enable network execution." in new_scan
    assert "data-assessment-form" in new_scan


@pytest.mark.django_db
def test_pending_approval_dialog_records_real_decision_and_returns_to_run(
    client, tmp_path, settings
):
    from datetime import UTC, datetime, timedelta

    from django.contrib.auth import get_user_model
    from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

    from vulnhunter.agent.models import (
        AgentTask,
        PermissionManifest,
        TaskStatus,
        ToolRisk,
    )
    from vulnhunter.agent.store import AgentStore
    from vulnhunter.approvals import ApprovalRequest, ApprovalStatus, ApprovalStore
    from vulnhunter.governance.service import bootstrap_administrator
    from vulnhunter.web.models import WebUserMapping

    pytest.importorskip("django")
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(tmp_path / "auth.db")
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.sqlite3")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator A",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    AgentStore(tmp_path / "agent.db").create_task(
        AgentTask(
            task_id="run-modal",
            objective="Review one bounded approval request safely.",
            status=TaskStatus.PAUSED_APPROVAL,
            permission_manifest=PermissionManifest(
                manifest_id="manifest-modal",
                role_id="orchestrator",
                skill_id="bounded-task-routing",
                allowed_actions=("evidence.inspect",),
                allowed_tools=("agent.echo",),
                allowed_risks=(ToolRisk.READ_ONLY,),
            ),
        )
    )
    approval_store = ApprovalStore(tmp_path / "approvals.sqlite3")
    instant = datetime.now(UTC)
    approval_store.create(
        ApprovalRequest(
            request_id="approval-modal",
            campaign_id="campaign-modal",
            run_id="run-modal",
            action_manifest_sha256="a" * 64,
            requested_by="orchestrator-a",
            summary="Approve the bounded local evidence action.",
            risk_summary="Read-only local evidence access.",
            requested_at=instant,
            expires_at=instant + timedelta(hours=1),
        )
    )

    user = get_user_model().objects.create_user(
        username="admin-ui",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="admin-a",
        product_roles=["system-administrator"],
    )
    client.force_login(user)

    detail = client.get("/agent/runs/run-modal/")
    assert detail.status_code == 200
    assert b'id="vh-approval-dialog"' in detail.content
    assert b'value="approve_once"' in detail.content
    assert b'value="deny_continue_safely"' in detail.content

    decision = client.post(
        "/approvals/approval-modal/decision/",
        {
            "decision": "approve_once",
            "reason": "Approved for this bounded local test.",
            "next": "/agent/runs/run-modal/",
        },
    )
    assert decision.status_code == 302
    assert decision["Location"].endswith("/agent/runs/run-modal/")
    assert approval_store.get("approval-modal").status == ApprovalStatus.APPROVED

    refreshed = client.get("/agent/runs/run-modal/")
    assert refreshed.status_code == 200
    assert b'id="vh-approval-dialog"' not in refreshed.content


@pytest.mark.django_db
def test_approved_navigation_routes_render_for_a_multi_role_operator(client, tmp_path, settings):
    from django.contrib.auth import get_user_model
    from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

    from vulnhunter.agent.store import AgentStore
    from vulnhunter.authorization.store import AuthorizationStore
    from vulnhunter.governance.service import bootstrap_administrator
    from vulnhunter.web.models import WebUserMapping

    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(tmp_path / "auth.db")
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.sqlite3")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

    AuthorizationStore.from_path(tmp_path / "auth.db").initialize()
    AgentStore(tmp_path / "agent.db")
    governance = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance,
        reviewer_id="admin-blueprint",
        display_name="Blueprint Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    user = get_user_model().objects.create_user(
        username="blueprint-admin",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="admin-blueprint",
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
    client.force_login(user)

    routes = (
        "/authorizations/",
        "/scans/new/",
        "/scans/",
        "/findings/",
        "/reviews/",
        "/adjudications/",
        "/campaigns/",
        "/releases/",
        "/datasets/",
        "/models/",
        "/audit/",
        "/reports/",
        "/settings/",
    )
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, route

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    for label in (
        b"Authorizations",
        b"New Scan",
        b"Scan Runs",
        b"Review Queue",
        b"Adjudications",
        b"Releases",
        b"Datasets",
        b"Models",
        b"Audit",
    ):
        assert label in dashboard.content


@pytest.mark.django_db
def test_navigation_is_filtered_by_product_role():
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import WebUserMapping
    from vulnhunter.web.services import navigation_for

    user = get_user_model().objects.create_user(
        username="reviewer-nav",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="reviewer-nav",
        product_roles=["reviewer"],
    )

    labels = {str(item["label"]) for item in navigation_for(user)}
    assert labels == {"Dashboard", "Findings", "Review Queue", "Reports"}
    assert "New Scan" not in labels
    assert "Adjudications" not in labels
    assert "Settings" not in labels
