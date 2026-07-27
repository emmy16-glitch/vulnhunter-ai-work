import json
from pathlib import Path

import pytest
from django.urls import resolve

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "vulnhunter" / "web"
TEMPLATES = WEB / "templates" / "web"
STATIC = WEB / "static" / "web"
LISTING = TEMPLATES / "agent_runs.html"
DETAIL = TEMPLATES / "agent_run_detail.html"
CONVERSATION = TEMPLATES / "conversation.html"
INSPECTOR = TEMPLATES / "_mobile_analysis_inspector.html"
BASE = TEMPLATES / "base.html"
CSS = STATIC / "workspace-polish.css"
SCRIPT = STATIC / "workspace-state.js"
BLUEPRINT_NAVIGATION = ROOT / "config" / "product_interface" / "navigation.json"
BLUEPRINT_PAGES = ROOT / "config" / "product_interface" / "pages.json"
URLS = WEB / "urls.py"
AUDIT_VIEWS = WEB / "audit_views.py"
FINDINGS_VIEWS = WEB / "findings_views.py"
REPORT_VIEWS = WEB / "report_views.py"
OPERATIONS_VIEWS = WEB / "operations_views.py"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_canonical_navigation_matches_the_unified_product():
    navigation = json.loads(_text(BLUEPRINT_NAVIGATION))
    sections = [section["label"] for section in navigation["sections"]]
    assert sections == [
        "Overview",
        "Collection",
        "Analysis",
        "Independent Review",
        "Governance",
        "Intelligence",
        "Assurance",
        "System",
    ]

    labels = [
        item["label"] for section in navigation["sections"] for item in section.get("items", [])
    ]
    assert labels == [
        "Assessment Workspace",
        "Authorizations",
        "Assessment History",
        "Findings",
        "Review Queue",
        "Adjudications",
        "Campaigns",
        "Releases",
        "Datasets",
        "Analysis Services",
        "Audit Log",
        "Reports",
        "Settings",
    ]
    assert len(labels) == len(set(labels))



def test_every_blueprint_page_route_resolves_to_the_runtime_router():
    pages = json.loads(_text(BLUEPRINT_PAGES))["pages"]
    for page in pages:
        segments = [
            "contract-sample" if segment.startswith(":") else segment
            for segment in page["route"].split("/")
        ]
        runtime_path = "/".join(segments) or "/"
        if runtime_path != "/" and not runtime_path.endswith("/"):
            runtime_path += "/"
        match = resolve(runtime_path)
        assert match.url_name, (page["page_id"], runtime_path)

def test_canonical_routes_and_legacy_aliases_are_explicit():
    urls = _text(URLS)
    for route_name in (
        "web-authorization-list",
        "web-authorization-detail",
        "web-authorization-revoke",
        "web-new-scan",
        "web-scan-run-list",
        "web-scan-run-detail",
        "web-findings-overview",
        "web-oracle-overview",
        "web-approval-list",
        "web-review-queue",
        "web-adjudication-queue",
        "web-release-list",
        "web-reports-overview",
        "web-audit-overview",
        "web-mobile-analysis",
        "web-agent-run-detail",
    ):
        assert route_name in urls

    assert 'RedirectView.as_view(url="/?intent=new-assessment"' in urls
    assert '"mobile-analysis/",\n        dashboard_dispatch_views.dashboard_view' in urls
    assert 'RedirectView.as_view(pattern_name="web-scan-run-detail"' in urls
    assert urls.count('path(\n        "scans/<str:run_id>/"') == 1
    assert "audit_views.audit_overview_view" in urls
    assert "findings_views.findings_overview_view" in urls
    assert "report_views.reports_overview_view" in urls
    assert "oracle_views" not in urls


def test_final_tokens_shared_shell_and_responsive_breakpoints_are_present():
    css = _text(CSS).lower()
    for token in (
        "--vh-final-bg: #0a0d13",
        "--vh-final-sidebar: 264px",
        "--vh-final-topbar: 64px",
        "--vh-final-focus: #93c5fd",
        "grid-template-columns: minmax(0, 1fr) 380px",
        "@media (max-width: 1279px)",
        "@media (max-width: 767px)",
        "min-height: 44px",
        "prefers-reduced-motion",
    ):
        assert token in css

    base = _text(BASE)
    conversation = _text(CONVERSATION)
    assert "{% block extra_styles %}" in base
    assert "{% block extra_scripts %}" in base
    assert "assessment-modal.js" not in base
    assert "conversation.js" not in base
    assert conversation.count("conversation-mobile-deferred-tools.js") == 1
    assert conversation.count("conversation-mobile-deferred-tools.css") == 1


def test_unified_workspace_is_interactive_and_backend_truthful():
    conversation = _text(CONVERSATION)
    inspector = _text(INSPECTOR)
    script = _text(SCRIPT)

    for token in (
        "data-state-authorization",
        "data-state-scope",
        "data-state-approval",
        "data-state-active",
        "data-conversation-form",
        "data-conversation-attach",
        "data-approval-confirm",
        "data-analysis-inspector-open",
    ):
        assert token in conversation

    for token in (
        "Assessment Inspector",
        'role="tab"',
        'data-inspector-panel="overview"',
        'data-inspector-panel="findings"',
        'data-inspector-panel="artifacts"',
        'data-inspector-panel="graph"',
        "No finding is shown until a real worker observation",
    ):
        assert token in inspector

    assert "progress_percent" in script
    assert "A genuine numeric progress value is unavailable" in script
    assert "42%" not in conversation + inspector + script
    assert "acme-payments.com" not in conversation + inspector
    assert "CVE-2023-50287" not in conversation + inspector


def test_assessment_detail_remains_evidence_first_and_truthful():
    listing = _text(LISTING)
    detail = _text(DETAIL)
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
    assert "run.attack_path" in detail
    assert "vh-workstream-panel" not in listing
    assert "vh-progress-100" not in detail
    assert "78%" not in detail
    assert "52%" not in detail
    assert "estimated percentage" in detail


def test_scanner_choice_remains_bounded_after_form_retirement():
    operations = _text(OPERATIONS_VIEWS)
    urls = _text(URLS)
    assert not (WEB / "assessment_views.py").exists()
    assert not (TEMPLATES / "new_scan.html").exists()
    assert not (TEMPLATES / "mobile_analysis.html").exists()
    assert not (STATIC / "assessment-modal.js").exists()
    assert "new_scan_view" not in operations
    assert "active_authorizations_view" not in operations
    assert "mobile_analysis_view" not in operations
    assert 'RedirectView.as_view(url="/?intent=new-assessment"' in urls
    assert '"scans/authorizations/"' not in urls
    web_text = "\n".join(path.read_text(encoding="utf-8") for path in WEB.rglob("*.py"))
    template_text = "\n".join(
        path.read_text(encoding="utf-8") for path in TEMPLATES.rglob("*.html")
    )
    assert "OpenVAS" not in web_text + template_text
    assert "Greenbone" not in web_text + template_text


def test_data_backed_pages_have_distinct_view_modules():
    assert "recent_audit_activity" in _text(AUDIT_VIEWS)
    assert "detail.findings" in _text(FINDINGS_VIEWS)
    assert "list_pilot_plan_records" in _text(REPORT_VIEWS)
    assert "url_has_allowed_host_and_scheme" in _text(OPERATIONS_VIEWS)


@pytest.mark.django_db
def test_pending_approval_records_a_real_decision_and_returns_to_the_canonical_run(
    client,
    tmp_path,
    settings,
):
    from datetime import UTC, datetime, timedelta

    from django.contrib.auth import get_user_model
    from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

    from vulnhunter.agent.models import AgentTask, PermissionManifest, TaskStatus, ToolRisk
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


@pytest.mark.django_db
def test_product_routes_render_and_retired_creation_routes_are_unified(
    client,
    tmp_path,
    settings,
):
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
        "/scans/",
        "/findings/",
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
        assert client.get(route).status_code == 200, route

    new_scan = client.get("/scans/new/")
    mobile = client.get("/mobile-analysis/")
    assert new_scan.status_code == 302
    assert new_scan["Location"] == "/?intent=new-assessment"
    assert mobile.status_code == 200
    assert b"Assessment Workspace" in mobile.content
    assert b"data-conversation-form" in mobile.content

    compatibility = client.get("/machine-oracle/")
    assert compatibility.status_code == 302
    assert compatibility["Location"].endswith("/scans/")
    assert client.get("/agent/runs/").status_code == 200

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    for label in (
        b"Assessment Workspace",
        b"Authorizations",
        b"Assessment History",
        b"Findings",
        b"Review Queue",
        b"Adjudications",
        b"Reports",
        b"Audit Log",
    ):
        assert label in dashboard.content
    assert b"Mobile APK Analysis" not in dashboard.content
    assert b"Machine Oracle" not in dashboard.content


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
    assert labels == {
        "Assessment Workspace",
        "Review Queue",
        "Reports",
        "Settings",
    }
    assert "Assessment History" not in labels
    assert "Approval Centre" not in labels
    assert "Mobile APK Analysis" not in labels


def test_overview_pages_do_not_repeat_sidebar_navigation():
    overview_pages = (
        "security_tools.html",
        "status.html",
        "approvals.html",
        "authorizations_overview.html",
        "dashboard.html",
        "audit_overview.html",
        "campaigns.html",
        "datasets_overview.html",
        "findings_overview.html",
        "governance_overview.html",
        "models_overview.html",
        "releases_overview.html",
        "reports_overview.html",
        "review_queue.html",
        "roles.html",
        "settings_overview.html",
        "skills.html",
    )
    for name in overview_pages:
        text = _text(TEMPLATES / name)
        assert "vh-product-heading-actions" not in text, name
        assert "vh-page-actions" not in text, name
        assert "Connected pages" not in text, name
        assert "Connected controls" not in text, name
        assert "Connected work areas" not in text, name
