from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from governance_test_support import ADMIN_SECRET, NOW, add_identity, make_governance_store

from vulnhunter.agent.store import AgentStore
from vulnhunter.approvals import ApprovalRequest, ApprovalStore
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.governance.service import bootstrap_administrator
from vulnhunter.product import ProductServiceError
from vulnhunter.product.service import ProductApplicationService, ProductPaths
from vulnhunter.web import lab_views
from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import navigation_for


@pytest.fixture
def deep_paths(tmp_path: Path, settings) -> Path:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(tmp_path / "authorization.db")
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.sqlite3")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = str(tmp_path / "evidence")
    settings.VULNHUNTER_ADVERSARY_LAB_DATABASE = str(tmp_path / "lab.sqlite3")
    settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT = str(tmp_path / "lab-workspaces")
    settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT = str(tmp_path / "lab-evidence")
    settings.VULNHUNTER_PILOT_PLAN_ROOT = str(tmp_path / "pilot-plans")
    AuthorizationStore.from_path(tmp_path / "authorization.db").initialize()
    AgentStore(tmp_path / "agent.db")
    governance = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance,
        reviewer_id="admin-a",
        display_name="Administrator A",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    for identity_id, roles in (
        ("operator-a", ("reviewer",)),
        ("approver-a", ("campaign_admin",)),
        ("reviewer-a", ("reviewer",)),
        ("adjudicator-a", ("adjudicator",)),
        ("auditor-a", ("reviewer",)),
        ("observer-a", ("reviewer",)),
    ):
        add_identity(
            governance,
            identity_id,
            f"{identity_id}-secret-1234",
            roles,
        )
    return tmp_path


def _user(
    *,
    username: str,
    identity: str,
    roles: list[str],
    password: str = "password-1234",
    staff: bool = False,
):
    user = get_user_model().objects.create_user(
        username=username,
        password=password,
        is_staff=staff,
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id=identity,
        product_roles=roles,
    )
    return user


def _labels(user) -> tuple[str, ...]:
    return tuple(str(item["label"]) for item in navigation_for(user))


def _run(*, owner: str = "operator-a", run_id: str = "run-owned-by-operator"):
    return SimpleNamespace(
        run_id=run_id,
        objective="Private target https://internal.example.invalid/admin",
        selected_role="orchestrator",
        selected_skill="bounded-task-routing",
        current_state="running",
        proposed_action="evidence.inspect",
        requested_tool="nuclei",
        risk_classification="passive",
        policy_result="allowed",
        policy_reason="Bounded local plan.",
        approval_requirement=False,
        approval_state=SimpleNamespace(value="not_required", __str__=lambda self: "not_required"),
        execution_state="running",
        evaluation_result=None,
        retry_decision=None,
        created_at=NOW,
        updated_at=NOW,
        final_event_sha256="a" * 64,
        denial_or_failure_reason=None,
        registry_validation_result="allowed",
        registry_validation_reason="Validated.",
        workflow_state="running",
        execution_enabled=True,
        execution_blocking_reason=None,
        authorization_id="authorization-one",
        plan_digest="b" * 64,
        readiness={},
        assessment_owner=owner,
        planner_output=None,
        input_summary=None,
        scope_summary="https://internal.example.invalid/admin",
        requested_operation="evidence.inspect",
        audit_references=(),
        recent_events=(),
        command_plan_summary={},
        findings=(
            {
                "evidence_id": "finding-cross-scope",
                "title": "Cross-scope evidence",
                "severity": "high",
                "confidence": "high",
                "verification": "verified",
                "target_reference": "https://internal.example.invalid/admin",
            },
        ),
        artifacts=(),
        attack_path=(),
    )


@pytest.mark.django_db
def test_navigation_respects_page_roles_and_does_not_offer_dead_destinations(deep_paths) -> None:
    reviewer = _user(username="reviewer", identity="reviewer-a", roles=["reviewer"])
    adjudicator = _user(
        username="adjudicator", identity="adjudicator-a", roles=["adjudicator"]
    )
    auditor = _user(username="auditor", identity="auditor-a", roles=["security-auditor"])
    approver = _user(username="approver", identity="approver-a", roles=["campaign-approver"])
    observer = _user(username="observer", identity="observer-a", roles=["read-only-observer"])

    assert "Review Queue" in _labels(reviewer)
    assert "Findings" not in _labels(reviewer)
    assert "Adjudications" not in _labels(reviewer)
    assert "Adjudications" in _labels(adjudicator)
    assert "Findings" not in _labels(adjudicator)
    assert "Review Queue" not in _labels(adjudicator)
    assert "Review Queue" not in _labels(auditor)
    assert "Adjudications" not in _labels(auditor)
    assert "Analysis Services" not in _labels(approver)
    assert _labels(observer) == (
        "Assessment Workspace",
        "Assessment History",
        "Campaigns",
        "Reports",
        "Settings",
    )


@pytest.mark.django_db
def test_role_specific_queue_and_model_routes_fail_closed(deep_paths, client) -> None:
    auditor = _user(username="route-auditor", identity="auditor-a", roles=["security-auditor"])
    client.force_login(auditor)
    assert client.get("/reviews/").status_code == 403
    assert client.get("/adjudications/").status_code == 403

    approver = _user(
        username="route-approver", identity="approver-a", roles=["campaign-approver"]
    )
    client.force_login(approver)
    assert client.get("/models/").status_code == 403


@pytest.mark.django_db
def test_observer_summary_pages_do_not_disclose_scope_or_detail_links(deep_paths, client) -> None:
    observer = _user(
        username="summary-observer",
        identity="observer-a",
        roles=["read-only-observer"],
    )
    run = _run()
    campaign = SimpleNamespace(
        campaign_id="secret-campaign-id",
        title="Secret Campaign",
        status="active",
        scope_summary=("https://internal.example.invalid/",),
        application_count=2,
        scan_count=4,
        release_manifest_state="not_released",
    )
    service = SimpleNamespace(
        list_agent_runs=lambda: (run,),
        list_campaigns=lambda: (campaign,),
    )
    client.force_login(observer)
    with (
        patch("vulnhunter.web.unified_assessment_views.product_service", return_value=service),
        patch("vulnhunter.web.views.product_service", return_value=service),
    ):
        runs = client.get("/scans/")
        campaigns = client.get("/campaigns/")

    assert runs.status_code == 200
    assert b"Assessment summary" in runs.content
    assert run.objective.encode() not in runs.content
    assert run.run_id.encode() not in runs.content
    assert run.scope_summary.encode() not in runs.content
    assert b"Open assessment" not in runs.content
    assert campaigns.status_code == 200
    assert b"Campaign summary" in campaigns.content
    assert campaign.campaign_id.encode() not in campaigns.content
    assert campaign.scope_summary[0].encode() not in campaigns.content
    assert b"Open campaign" not in campaigns.content
    assert client.get(f"/scans/{run.run_id}/").status_code == 403
    assert client.get(f"/campaigns/{campaign.campaign_id}/").status_code == 403


@pytest.mark.django_db
def test_auditor_can_read_cross_owner_findings_and_activity(deep_paths, client) -> None:
    auditor = _user(
        username="cross-scope-auditor",
        identity="auditor-a",
        roles=["security-auditor"],
    )
    run = _run()
    service = SimpleNamespace(
        list_agent_runs=lambda: (run,),
        get_agent_run=lambda _run_id: run,
    )
    client.force_login(auditor)
    with (
        patch("vulnhunter.web.findings_views.product_service", return_value=service),
        patch("vulnhunter.web.views.product_service", return_value=service),
        patch("vulnhunter.web.stream_views.product_service", return_value=service),
    ):
        findings = client.get("/findings/")
        activity = client.get(f"/agent/runs/{run.run_id}/activity/")
        stream = client.get(f"/agent/runs/{run.run_id}/activity/stream/")

    assert findings.status_code == 200
    assert b"Cross-scope evidence" in findings.content
    assert activity.status_code == 200
    assert stream.status_code == 200


@pytest.mark.django_db
def test_system_administrator_can_control_cross_owner_run(deep_paths, client) -> None:
    administrator = _user(
        username="cross-scope-admin",
        identity="admin-a",
        roles=["system-administrator"],
        staff=True,
    )
    run = _run()
    service = SimpleNamespace(get_agent_run=lambda _run_id: run)
    client.force_login(administrator)
    with patch("vulnhunter.web.views.product_service", return_value=service):
        response = client.get(f"/agent/runs/{run.run_id}/stop/")
    assert response.status_code == 200
    assert b"Stop assessment" in response.content


@pytest.mark.django_db
def test_campaign_approver_login_does_not_open_admin_only_run_approval(deep_paths, client) -> None:
    _user(
        username="login-approver",
        identity="approver-a",
        roles=["campaign-approver"],
    )
    instant = datetime.now(UTC)
    ApprovalStore(Path(deep_paths / "approvals.sqlite3")).create(
        ApprovalRequest(
            request_id="pending-login-approval",
            campaign_id="campaign-one",
            run_id="run-needs-admin",
            action_manifest_sha256="c" * 64,
            requested_by="operator-a",
            summary="Approve one exact bounded execution plan.",
            risk_summary="Requires an administrator decision.",
            requested_at=instant,
            expires_at=instant + timedelta(hours=1),
        )
    )
    response = client.post(
        "/login/",
        {"username": "login-approver", "password": "password-1234"},
    )
    assert response.status_code == 302
    assert response["Location"].endswith("/scans/")
    assert "run-needs-admin" not in response["Location"]


@pytest.mark.django_db
def test_campaign_approver_sees_read_only_execution_approval(deep_paths, client) -> None:
    approver = _user(
        username="readonly-approval-approver",
        identity="approver-a",
        roles=["campaign-approver"],
    )
    instant = datetime.now(UTC)
    ApprovalStore(Path(deep_paths / "approvals.sqlite3")).create(
        ApprovalRequest(
            request_id="readonly-execution-approval",
            campaign_id="campaign-one",
            run_id="run-one",
            action_manifest_sha256="e" * 64,
            requested_by="operator-a",
            summary="Approve one exact bounded execution plan.",
            risk_summary="Administrator decision required.",
            requested_at=instant,
            expires_at=instant + timedelta(hours=1),
        )
    )
    client.force_login(approver)
    response = client.get("/approvals/readonly-execution-approval/")
    assert response.status_code == 200
    assert b"Read-only approval record" in response.content
    assert b"Record decision" not in response.content
    assert b'<form method="post"' not in response.content


@pytest.mark.django_db
def test_corrupt_approval_store_fails_closed_without_internal_paths(
    deep_paths,
    client,
) -> None:
    approver = _user(
        username="corrupt-approval-approver",
        identity="approver-a",
        roles=["campaign-approver"],
    )
    approval_path = Path(deep_paths / "approvals.sqlite3")
    approval_path.write_bytes(b"not a sqlite database at /private/runtime/approvals")
    client.force_login(approver)

    listing = client.get("/approvals/")
    detail = client.get("/approvals/example-approval/")

    assert listing.status_code == 503
    assert detail.status_code == 503
    for response in (listing, detail):
        assert b"Approval records are temporarily unavailable" in response.content
        assert str(deep_paths).encode() not in response.content
        assert b"sqlite" not in response.content.lower()


@pytest.mark.django_db
def test_conversation_hides_authorization_backend_exceptions(deep_paths, client) -> None:
    operator = _user(
        username="conversation-safe-error",
        identity="operator-a",
        roles=["campaign-operator"],
    )
    workflow = SimpleNamespace(
        list_authorizations=lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("/private/runtime/authorization.db is not a database")
        )
    )
    client.force_login(operator)
    with patch(
        "vulnhunter.web.conversational_views.AssessmentWorkflowService.from_settings",
        return_value=workflow,
    ):
        response = client.post("/workspace/message/", {"message": "scan the current target"})

    assert response.status_code == 503
    payload = response.json()
    copy = payload["message"]["content"]
    assert copy == "The authorization service is temporarily unavailable."
    assert "/private/runtime" not in copy
    assert "database" not in copy.lower()


@pytest.mark.django_db
def test_operator_pending_run_does_not_link_to_inaccessible_approval_centre(
    deep_paths,
    client,
) -> None:
    operator = _user(
        username="pending-operator",
        identity="operator-a",
        roles=["campaign-operator"],
    )
    run = _run()
    run.approval_state = SimpleNamespace(value="pending", __str__=lambda self: "pending")
    instant = datetime.now(UTC)
    ApprovalStore(Path(deep_paths / "approvals.sqlite3")).create(
        ApprovalRequest(
            request_id="operator-pending-approval",
            campaign_id="campaign-one",
            run_id=run.run_id,
            action_manifest_sha256="d" * 64,
            requested_by="operator-a",
            summary="Approve one exact bounded execution plan.",
            risk_summary="Independent decision required.",
            requested_at=instant,
            expires_at=instant + timedelta(hours=1),
        )
    )
    service = SimpleNamespace(get_agent_run=lambda _run_id: run)
    client.force_login(operator)
    with patch("vulnhunter.web.unified_assessment_views.product_service", return_value=service):
        response = client.get(f"/scans/{run.run_id}/")
    assert response.status_code == 200
    assert b"Waiting for authorised approver" in response.content
    assert b"Open Approval Centre" not in response.content


@pytest.mark.django_db
def test_independent_approver_can_open_cross_owner_active_validation(deep_paths) -> None:
    approver = _user(
        username="lab-approver",
        identity="approver-a",
        roles=["campaign-approver"],
        staff=True,
    )
    request = RequestFactory().get("/active-validation/example/")
    request.user = approver
    run = _run()
    with patch(
        "vulnhunter.web.lab_views.product_service",
        return_value=SimpleNamespace(get_agent_run=lambda _run_id: run),
    ):
        actor, resolved = lab_views._assessment_for_actor(request, run.run_id)
    assert actor.governance_identity.reviewer_id == "approver-a"
    assert resolved is run


@pytest.mark.django_db
def test_unknown_object_routes_return_404_instead_of_500(deep_paths, client) -> None:
    auditor = _user(
        username="missing-object-auditor",
        identity="auditor-a",
        roles=["security-auditor"],
    )
    client.force_login(auditor)
    for route in (
        "/campaigns/missing-campaign/",
        "/readiness/missing-campaign/",
        "/releases/missing-campaign/",
        "/datasets/missing-campaign/",
        "/roles/missing-role/",
        "/skills/missing-skill/",
        "/scans/missing-run/",
        "/agent/runs/missing-run/",
        "/agent/runs/missing-run/activity/",
    ):
        assert client.get(route).status_code == 404, route


def test_product_service_translates_storage_and_registry_errors(tmp_path: Path) -> None:
    authorization = tmp_path / "authorization.db"
    governance = tmp_path / "governance.db"
    agent = tmp_path / "agent.db"
    AuthorizationStore.from_path(authorization).initialize()
    make_governance_store(tmp_path)
    AgentStore(agent)
    service = ProductApplicationService(
        ProductPaths(
            authorization_database=authorization,
            governance_database=governance,
            agent_database=agent,
            role_registry_root=Path("config/roles"),
            product_spec_root=Path("config/product_interface"),
            runtime_config=Path("config/agent_runtime/runtime.json"),
            evidence_root=tmp_path / "evidence",
        )
    )
    with pytest.raises(ProductServiceError, match="missing-campaign"):
        service.get_campaign("missing-campaign")
    with pytest.raises(ProductServiceError, match="missing-role"):
        service.get_role("missing-role")
    with pytest.raises(ProductServiceError, match="missing-skill"):
        service.get_skill("missing-skill")

    agent.write_bytes(b"not a sqlite database")
    with pytest.raises(ProductServiceError):
        service.list_agent_runs()
    assert service.load_status().agent_runtime.state.value == "invalid"

    governance.write_bytes(b"not a sqlite database")
    with pytest.raises(ProductServiceError):
        service.list_campaigns()
    dashboard = service.load_dashboard()
    assert dashboard.status.governance_store.state.value == "invalid"

    status = service.load_status()
    for capability in (
        status.authorization_store,
        status.governance_store,
        status.role_registry,
        status.agent_runtime,
        status.readiness,
        status.audit_evidence,
    ):
        assert str(tmp_path) not in capability.detail
        assert "sqlite" not in capability.detail.lower()
        assert (
            capability.evidence_reference is None
            or str(tmp_path) not in capability.evidence_reference
        )

    missing_service = ProductApplicationService(
        ProductPaths(
            authorization_database=tmp_path / "missing-authorization.db",
            governance_database=tmp_path / "missing-governance.db",
            agent_database=tmp_path / "missing-agent.db",
            role_registry_root=tmp_path / "missing-roles",
            product_spec_root=Path("config/product_interface"),
            runtime_config=Path("config/agent_runtime/runtime.json"),
            evidence_root=tmp_path / "missing-evidence",
        )
    )
    missing_status = missing_service.load_status()
    for capability in (
        missing_status.authorization_store,
        missing_status.governance_store,
        missing_status.role_registry,
        missing_status.agent_runtime,
    ):
        assert str(tmp_path) not in capability.detail
        assert (
            capability.evidence_reference is None
            or str(tmp_path) not in capability.evidence_reference
        )
    with pytest.raises(ProductServiceError, match="Campaign records could not be loaded safely"):
        missing_service.list_campaigns()
    with pytest.raises(ProductServiceError, match="Assessment runs could not be loaded safely"):
        missing_service.list_agent_runs()
    with pytest.raises(ProductServiceError, match="Role registry could not be read safely"):
        missing_service.list_roles()


def test_cross_scope_and_summary_contracts_are_centralized() -> None:
    root = Path(__file__).resolve().parents[2]
    web = root / "vulnhunter" / "web"
    owner_only_consumers = {
        "conversational_views.py",
        "middleware.py",
    }
    for path in web.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "run_visible_to_actor(" in text and path.name not in owner_only_consumers | {
            "services.py",
        }:
            raise AssertionError(f"{path.name} bypasses the shared cross-scope read contract")
