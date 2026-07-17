from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "vulnhunter" / "web"
TEMPLATES = WEB / "templates" / "web"
STATIC = WEB / "static" / "web"
BASE = TEMPLATES / "base.html"
LISTING = TEMPLATES / "agent_runs.html"
DETAIL = TEMPLATES / "agent_run_detail.html"
NEW_ASSESSMENT = TEMPLATES / "new_scan.html"
CSS = STATIC / "app.css"
PRODUCT_WIDE_CSS = STATIC / "product-wide.css"
SCRIPT = STATIC / "app.js"
NAVIGATION = WEB / "templatetags" / "vh_navigation.py"
URLS = WEB / "urls.py"
ASSESSMENT_VIEWS = WEB / "assessment_views.py"
AUDIT_VIEWS = WEB / "audit_views.py"
FINDINGS_VIEWS = WEB / "findings_views.py"
REPORT_VIEWS = WEB / "report_views.py"
OPERATIONS_VIEWS = WEB / "operations_views.py"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_canonical_navigation_has_one_destination_per_capability():
    navigation = _text(NAVIGATION)
    for section in (
        "Overview",
        "Operations",
        "Review",
        "Governance",
        "Intelligence",
        "System",
    ):
        assert f'"section_label": "{section}"' in navigation
    labels = (
        "Dashboard",
        "Authorizations",
        "Assessments",
        "Findings",
        "Machine Oracle",
        "Approval Centre",
        "Review Queue",
        "Adjudications",
        "Campaigns",
        "Releases",
        "Reports",
        "Policies",
        "Datasets",
        "Models",
        "Mobile APK Analysis",
        "Integrations & Tools",
        "Audit Log",
        "Settings",
    )
    for label in labels:
        assert navigation.count(f'"label": "{label}"') == 1
    assert '"label": "New Scan"' not in navigation
    assert '"label": "Scan Runs"' not in navigation


def test_canonical_routes_and_legacy_redirects_are_explicit():
    urls = _text(URLS)
    for route_name in (
        "web-authorization-list",
        "web-new-scan",
        "web-scan-run-list",
        "web-findings-overview",
        "web-oracle-overview",
        "web-approval-list",
        "web-review-queue",
        "web-adjudication-queue",
        "web-release-list",
        "web-reports-overview",
        "web-audit-overview",
    ):
        assert route_name in urls
    assert 'RedirectView.as_view(pattern_name="web-scan-run-list"' in urls
    assert 'RedirectView.as_view(pattern_name="web-scan-run-detail"' in urls
    assert "audit_views.audit_overview_view" in urls
    assert "oracle_views.oracle_overview_view" in urls
    assert "findings_views.findings_overview_view" in urls
    assert "report_views.reports_overview_view" in urls


def test_blueprint_tokens_and_responsive_breakpoints_are_present():
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
    product_css = _text(PRODUCT_WIDE_CSS)
    for token in (
        "100dvh",
        "@media (max-width: 1260px)",
        "@media (max-width: 1023px)",
        "@media (max-width: 760px)",
        "@media (max-width: 560px)",
        "overflow-x: auto",
    ):
        assert token in product_css
    script = _text(SCRIPT)
    assert 'window.matchMedia("(max-width: 1023px)").matches' in script
    assert "product-wide.css" in script


def test_assessment_workspace_is_interactive_and_backend_truthful():
    listing = _text(LISTING)
    detail = _text(DETAIL)
    script = _text(SCRIPT)
    for token in (
        "vh-workstream-panel",
        "vh-inspector",
        "vh-bottom-dock",
        "vh-stage-disclosure",
        "vh-output-panel",
        "data-attack-path",
        "data-attack-node",
    ):
        assert token in detail
    assert detail.count('role="tab"') >= 8
    assert "querySelector(\":scope > [role='tablist']\")" in script
    assert "run.attack_path" in detail
    assert "Nodes appear only" not in listing
    assert "vh-workstream-panel" not in listing
    assert "vh-progress-100" not in detail
    assert "78%" not in detail
    assert "52%" not in detail
    assert "estimated percentage" in detail
    for fake_value in (
        "acme-payments.com",
        "CVE-2023-50287",
        "/api/v1/users",
        "Nuclei v3.1.3",
        "6,421",
        "32 threads",
    ):
        assert fake_value not in listing + detail


def test_scanner_choice_is_bounded_to_automatic_or_nuclei():
    listing = _text(LISTING)
    new_assessment = _text(NEW_ASSESSMENT)
    view = _text(ASSESSMENT_VIEWS)
    modal_script = _text(STATIC / "assessment-modal.js")
    for template in (listing, new_assessment):
        assert 'name="scanner_engine"' in template
        assert 'value="automatic"' in template
        assert 'value="nuclei"' in template
    assert '_ALLOWED_SCANNER_ENGINES = {"automatic", "nuclei"}' in view
    assert "data-engine-select" in listing
    assert "engineSelect" in modal_script
    web_text = "\n".join(path.read_text(encoding="utf-8") for path in WEB.rglob("*.py"))
    template_text = "\n".join(
        path.read_text(encoding="utf-8") for path in TEMPLATES.rglob("*.html")
    )
    assert "OpenVAS" not in web_text + template_text


def test_data_backed_pages_have_distinct_view_modules():
    assert "recent_audit_activity" in _text(AUDIT_VIEWS)
    assert "detail.findings" in _text(FINDINGS_VIEWS)
    assert "list_pilot_plan_records" in _text(REPORT_VIEWS)
    assert "intelligence_status" in _text(WEB / "oracle_views.py")
    assert "url_has_allowed_host_and_scheme" in _text(OPERATIONS_VIEWS)


@pytest.mark.django_db
def test_pending_approval_dialog_records_real_decision_and_returns_to_canonical_run(
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

    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(tmp_path / "auth.db")
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.sqlite3")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = str(tmp_path / "evidence")
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

    detail = client.get("/scans/run-modal/")
    assert detail.status_code == 200
    assert b'id="vh-approval-dialog"' in detail.content
    assert b'value="approve_once"' in detail.content
    assert b'value="deny_continue_safely"' in detail.content

    decision = client.post(
        "/approvals/approval-modal/decision/",
        {
            "decision": "approve_once",
            "reason": "Approved for this bounded local test.",
            "next": "/scans/run-modal/",
        },
    )
    assert decision.status_code == 302
    assert decision["Location"].endswith("/scans/run-modal/")
    assert approval_store.get("approval-modal").status == ApprovalStatus.APPROVED

    refreshed = client.get("/scans/run-modal/")
    assert refreshed.status_code == 200
    assert b'id="vh-approval-dialog"' not in refreshed.content


@pytest.mark.django_db
def test_product_routes_render_for_a_multi_role_operator(client, tmp_path, settings):
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
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = str(tmp_path / "evidence")
    settings.VULNHUNTER_PILOT_PLAN_ROOT = str(tmp_path / "pilot-plans")
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
        "/machine-oracle/",
        "/approvals/",
        "/reviews/",
        "/adjudications/",
        "/campaigns/",
        "/releases/",
        "/datasets/",
        "/models/",
        "/audit/",
        "/reports/",
        "/governance/",
        "/settings/",
    )
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, route

    legacy_list = client.get("/agent/runs/")
    assert legacy_list.status_code == 302
    assert legacy_list["Location"].endswith("/scans/")

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    for label in (
        b"Authorizations",
        b"Assessments",
        b"Findings",
        b"Machine Oracle",
        b"Approval Centre",
        b"Review Queue",
        b"Adjudications",
        b"Reports",
        b"Audit Log",
    ):
        assert label in dashboard.content


@pytest.mark.django_db
def test_navigation_is_filtered_by_product_role():
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import WebUserMapping
    from vulnhunter.web.templatetags.vh_navigation import canonical_navigation

    user = get_user_model().objects.create_user(
        username="reviewer-nav",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="reviewer-nav",
        product_roles=["reviewer"],
    )

    labels = {str(item["label"]) for item in canonical_navigation(user)}
    assert labels == {"Dashboard", "Findings", "Review Queue", "Reports"}
    assert "Assessments" not in labels
    assert "Approval Centre" not in labels
    assert "Settings" not in labels
