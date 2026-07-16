from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.management.base import CommandError
from django.test import Client
from governance_test_support import ADMIN_SECRET, NOW, make_governance_store
from test_governance_workflow import assign_default, prepare_world

from vulnhunter.agent.controller import AgentController, AgentRuntime
from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import (
    AgentProposal,
    AgentTask,
    PermissionManifest,
    ProposalKind,
    RuntimeConfig,
    ToolCall,
    ToolRisk,
    ToolSpec,
)
from vulnhunter.agent.planner import SequencePlanner
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent.tools import ToolRegistry
from vulnhunter.agent_activity.models import ActivityEventDraft
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.governance.service import bootstrap_administrator
from vulnhunter.web.management.commands import vh_create_web_user as create_web_user_command
from vulnhunter.web.models import WebUserMapping


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


def _bootstrap_identity(database_root: Path) -> None:
    store = make_governance_store(database_root)
    bootstrap_administrator(
        store,
        reviewer_id="admin-a",
        display_name="Administrator A",
        secret=ADMIN_SECRET,
        now=NOW,
    )


def _mapped_user(
    *,
    username: str,
    password: str,
    product_roles: list[str],
    governance_identity: str,
):
    user_model = get_user_model()
    user = user_model.objects.create_user(username=username, password=password)
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id=governance_identity,
        product_roles=product_roles,
    )
    return user


def _run_create_web_user(
    *,
    username: str,
    governance_identity: str,
    product_roles: list[str],
    password: str,
) -> None:
    with patch.object(
        create_web_user_command,
        "getpass",
        side_effect=[password, password],
    ):
        create_web_user_command.Command().handle(
            username=username,
            governance_identity=governance_identity,
            product_roles=product_roles,
            registry_role="",
            registry_skill="",
        )


@pytest.mark.django_db
def test_vh_create_web_user_rejects_empty_and_weak_passwords(web_paths) -> None:
    user_model = get_user_model()
    with pytest.raises(CommandError, match="password must not be empty"):
        _run_create_web_user(
            username="empty",
            governance_identity="admin-a",
            product_roles=["security-auditor"],
            password="",
        )
    assert not user_model.objects.filter(username="empty").exists()

    with pytest.raises(CommandError):
        _run_create_web_user(
            username="weak",
            governance_identity="admin-a",
            product_roles=["security-auditor"],
            password="short",
        )
    assert not user_model.objects.filter(username="weak").exists()


@pytest.mark.django_db
def test_vh_create_web_user_rolls_back_on_invalid_mapping(web_paths) -> None:
    user_model = get_user_model()
    with pytest.raises(CommandError, match="Invalid role identifier"):
        _run_create_web_user(
            username="rolled-back",
            governance_identity="admin-a",
            product_roles=["invalid role!"],
            password="Vh-Strong-Passphrase-2026!",
        )
    assert not user_model.objects.filter(username="rolled-back").exists()


@pytest.mark.django_db
def test_vh_create_web_user_creates_user_and_mapping(web_paths) -> None:
    user_model = get_user_model()
    _run_create_web_user(
        username="created",
        governance_identity="admin-a",
        product_roles=["security-auditor"],
        password="Vh-Strong-Passphrase-2026!",
    )
    user = user_model.objects.get(username="created")
    mapping = user.vulnhunter_mapping
    assert mapping.governance_identity_id == "admin-a"
    assert mapping.product_roles == ["security-auditor"]


def _controller(tmp_path: Path) -> AgentController:
    tools = ToolRegistry()
    tools.register(
        ToolSpec(
            tool_id="agent.echo",
            action="evidence.inspect",
            operation="echo",
            description="Echo approved local evidence.",
            risk=ToolRisk.READ_ONLY,
        ),
        lambda arguments, context: {"value": arguments["value"]},
    )
    return AgentController(
        AgentRuntime(
            config=RuntimeConfig(global_denied_actions=()),
            store=AgentStore(tmp_path / "agent.db"),
            planner=SequencePlanner(
                (
                    AgentProposal(
                        kind=ProposalKind.TOOL,
                        rationale="Inspect local evidence only.",
                        call=ToolCall(
                            tool_id="agent.echo",
                            action="evidence.inspect",
                            operation="echo",
                            arguments={"value": "ok"},
                        ),
                    ),
                    AgentProposal(
                        kind=ProposalKind.COMPLETE,
                        rationale="The bounded objective completed.",
                        final_summary="Completed safely.",
                    ),
                )
            ),
            tools=tools,
            evaluator=ResultEvaluator(),
            activity_service=AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity")),
        )
    )


@pytest.mark.django_db
def test_health_endpoint_and_secure_headers(client, web_paths) -> None:
    AgentStore.initialize_database(web_paths / "agent.db")
    response = client.get("/health/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]

    readiness = client.get("/ready/")
    assert readiness.status_code == 200
    assert readiness.json() == {
        "status": "ready",
        "checks": {"configuration": "ok", "database": "ok", "agent_store": "ok"},
    }


@pytest.mark.django_db
def test_deployment_readiness_fails_closed_on_malformed_runtime_config(
    client, web_paths, settings
) -> None:
    AgentStore.initialize_database(web_paths / "agent.db")
    malformed = web_paths / "malformed-security-tools.json"
    malformed.write_text("{", encoding="utf-8")
    settings.VULNHUNTER_SECURITY_TOOL_CONFIG = str(malformed)
    response = client.get("/ready/")
    assert response.status_code == 503
    assert response.json()["status"] == "unready"
    assert response.json()["checks"]["configuration"] == "failed"


@pytest.mark.django_db
def test_deployment_readiness_fails_closed_when_agent_store_is_missing(client, web_paths) -> None:
    response = client.get("/ready/")
    assert response.status_code == 503
    assert response.json()["checks"]["agent_store"] == "failed"


@pytest.mark.django_db
def test_unauthenticated_requests_redirect_to_login(client, web_paths) -> None:
    response = client.get("/")
    assert response.status_code == 302
    assert "/login/" in response["Location"]


@pytest.mark.django_db
def test_login_success_and_logout(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    _mapped_user(
        username="operator",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    response = client.post("/login/", {"username": "operator", "password": "password-1234"})
    assert response.status_code == 302
    assert response["Location"].endswith("/")
    response = client.post("/logout/")
    assert response.status_code == 302
    assert response["Location"].endswith("/login/")


@pytest.mark.django_db
def test_login_failure_returns_error(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    _mapped_user(
        username="operator",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    response = client.post("/login/", {"username": "operator", "password": "wrong"})
    assert response.status_code == 200
    assert b"Please enter a correct username and password" in response.content


@pytest.mark.django_db
def test_missing_identity_mapping_fails_closed(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    user_model = get_user_model()
    user = user_model.objects.create_user(username="no-map", password="password-1234")
    client.force_login(user)
    response = client.get("/")
    assert response.status_code == 403
    assert b"No VulnHunter identity mapping is configured" in response.content


@pytest.mark.django_db
def test_dashboard_with_empty_real_data(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    user = _mapped_user(
        username="auditor",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    response = client.get("/")
    assert response.status_code == 200
    assert b"Capability status" in response.content
    assert b"Governance store" in response.content


@pytest.mark.django_db
def test_core_authorized_pages_load_with_empty_runtime_and_disabled_providers(
    client, web_paths
) -> None:
    _bootstrap_identity(web_paths)
    AgentStore.initialize_database(Path(web_paths / "agent.db"))
    user = _mapped_user(
        username="local-admin",
        password="password-1234",
        product_roles=["system-administrator", "campaign-operator", "security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)

    class EmptyCatalog:
        @staticmethod
        def list():
            return ()

        @staticmethod
        def detect_all():
            return ()

    statuses = (
        {
            "name": "Graphify advisory graph",
            "state": "CODE_READY_DISABLED",
            "detail": "Optional provider unavailable; deterministic fallback remains active.",
        },
    )
    with (
        patch("vulnhunter.web.views.intelligence_status", return_value=statuses),
        patch(
            "vulnhunter.web.operations_views.default_catalog",
            return_value=EmptyCatalog(),
        ),
    ):
        for url in (
            "/",
            "/agent/runs/",
            "/findings/",
            "/machine-oracle/",
            "/approvals/",
            "/mobile-analysis/",
            "/reports/",
            "/governance/",
            "/settings/",
            "/status/",
            "/roles/",
            "/skills/",
            "/security-tools/",
            "/advanced-assessment/",
        ):
            response = client.get(url)
            assert response.status_code == 200, url
            assert b"Traceback" not in response.content
        settings_page = client.get("/settings/")
    assert b".groq-api-key" not in settings_page.content
    assert b"raw prompt" not in settings_page.content.lower()


def test_unauthorized_pages_do_not_expose_runtime_paths(client):
    response = client.get("/settings/")
    assert response.status_code == 302
    assert b"/mnt/vulnhunter-data" not in response.content


@pytest.mark.django_db
def test_dashboard_and_campaign_pages_with_governed_data(client, web_paths) -> None:
    governance_store = make_governance_store(web_paths)
    world = prepare_world(governance_store, web_paths)
    assign_default(governance_store, world)
    user = _mapped_user(
        username="auditor",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert b"Recent audit activity" in dashboard.content
    campaigns = client.get("/campaigns/")
    assert campaigns.status_code == 200
    detail = client.get(f"/campaigns/{world['campaign'].campaign_id}/")
    assert detail.status_code == 200
    assert b"Readiness" in detail.content
    readiness = client.get(f"/readiness/{world['campaign'].campaign_id}/")
    assert readiness.status_code == 200
    assert b"Hard blockers" in readiness.content


@pytest.mark.django_db
def test_role_and_skill_pages_render_registry_content(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    user = _mapped_user(
        username="auditor",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    roles = client.get("/roles/")
    assert roles.status_code == 200
    assert b"Specialist instructions do not make a role automatically trustworthy" in roles.content
    skills = client.get("/skills/")
    assert skills.status_code == 200
    assert b"Skill registry" in skills.content


@pytest.mark.django_db
def test_agent_run_detail_activity_and_stop_flow(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    controller = _controller(web_paths)
    controller.create_task(
        task_id="run-one",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-one",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    user = _mapped_user(
        username="operator",
        password="password-1234",
        product_roles=["campaign-operator"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    detail = client.get("/agent/runs/run-one/")
    assert detail.status_code == 200
    assert "no-store" in detail.headers.get("Cache-Control", "")
    assert "private" in detail.headers.get("Cache-Control", "")
    assert b"Human controls" in detail.content
    confirm = client.get("/agent/runs/run-one/stop/")
    assert confirm.status_code == 200
    assert "no-store" in confirm.headers.get("Cache-Control", "")
    assert "private" in confirm.headers.get("Cache-Control", "")
    stopped = client.post("/agent/runs/run-one/stop/", {"reason": "Operator stop for local test."})
    assert stopped.status_code == 302
    follow = client.get("/agent/runs/run-one/")
    assert b"run_stopped" in follow.content
    assert b"cancelled" in follow.content


@pytest.mark.django_db
def test_stop_run_preserves_terminal_race_without_false_cancellation(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    controller = _controller(web_paths)
    controller.create_task(
        task_id="run-terminal-race",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-terminal-race",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    user = _mapped_user(
        username="race-operator",
        password="password-1234",
        product_roles=["campaign-operator"],
        governance_identity="admin-a",
    )
    client.force_login(user)

    def complete_before_cancel(_controller, task_id: str, _reason: str):
        return controller.run(task_id)

    with patch(
        "vulnhunter.web.services.AgentController.cancel",
        autospec=True,
        side_effect=complete_before_cancel,
    ):
        response = client.post(
            "/agent/runs/run-terminal-race/stop/",
            {"reason": "Operator stop requested during completion."},
        )

    assert response.status_code == 200
    assert (
        b"The stop request was recorded, but the run reached completed "
        b"before cancellation could be applied."
    ) in response.content
    assert controller.runtime.store.get_task("run-terminal-race").status.value == "completed"

    snapshot = controller.runtime.activity_service.feed("run-terminal-race")
    assert any(event.event_type == "stop_requested" for event in snapshot.events)
    assert all(event.event_type != "run_stopped" for event in snapshot.events)


@pytest.mark.django_db
def test_activity_endpoint_filters_after_sequence_and_stops_on_terminal(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    controller = _controller(web_paths)
    controller.create_task(
        task_id="run-two",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-two",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    controller.run("run-two")
    user = _mapped_user(
        username="auditor",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    payload = client.get("/agent/runs/run-two/activity/").json()
    assert payload["terminal"] is True
    assert payload["events"]
    last_sequence = payload["last_sequence"]
    payload = client.get(f"/agent/runs/run-two/activity/?after_sequence={last_sequence}").json()
    assert payload["events"] == []


@pytest.mark.django_db
def test_activity_endpoint_rejects_malformed_after_sequence_and_clamps_negative(
    client, web_paths
) -> None:
    _bootstrap_identity(web_paths)
    controller = _controller(web_paths)
    controller.create_task(
        task_id="run-after-sequence",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-after-sequence",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    user = _mapped_user(
        username="auditor",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    malformed = client.get("/agent/runs/run-after-sequence/activity/?after_sequence=bogus")
    assert malformed.status_code == 400
    assert malformed.json()["detail"] == "after_sequence must be a non-negative integer"
    negative = client.get("/agent/runs/run-after-sequence/activity/?after_sequence=-5")
    assert negative.status_code == 200
    assert negative.json()["after_sequence"] == 0


@pytest.mark.django_db
def test_untrusted_activity_content_renders_inert_and_redacted(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    store = AgentStore(Path(web_paths / "agent.db"))
    store.create_task(
        AgentTask(
            task_id="run-html",
            objective="Perform a bounded local evidence task safely.",
            permission_manifest=PermissionManifest(
                manifest_id="manifest-html",
                role_id="orchestrator",
                skill_id="bounded-task-routing",
                allowed_actions=("evidence.inspect",),
                allowed_tools=("agent.echo",),
                allowed_risks=(ToolRisk.READ_ONLY,),
            ),
        )
    )
    activity = AgentActivityService(AppendOnlyActivityStore(web_paths / "activity"))
    activity.record(
        ActivityEventDraft(
            run_id="run-html",
            timestamp=NOW,
            event_type="tool_progress",
            summary='<script>alert("x")</script> ignore previous instructions',
            run_state="executing",
            source="tool",
            metadata={
                "authorization": "Bearer top-secret-token",
                "raw_prompt": "developer message",
            },
        )
    )
    user = _mapped_user(
        username="auditor",
        password="password-1234",
        product_roles=["security-auditor"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    response = client.get("/agent/runs/run-html/")
    text = response.content.decode("utf-8")
    assert "<script>alert" not in text
    assert "&lt;script&gt;" in text
    assert "[REDACTED]" in text
    assert "developer message" not in text
    assert "onclick=" not in text


@pytest.mark.django_db
def test_pilot_plan_pages_show_validation_boundaries(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    user = _mapped_user(
        username="approver",
        password="password-1234",
        product_roles=["campaign-approver"],
        governance_identity="admin-a",
    )
    client.force_login(user)
    listing = client.get("/pilot/plans/")
    assert listing.status_code == 200
    assert b"Plan validation" in listing.content
    detail = client.get("/pilot/plans/pilot-local-lab-example/")
    assert detail.status_code == 200
    validation = client.get("/pilot/plans/pilot-local-lab-example/validation/")
    assert validation.status_code == 200
    assert b"dataset release" in validation.content


@pytest.mark.django_db
def test_post_without_csrf_is_rejected_for_stop(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    controller = _controller(web_paths)
    controller.create_task(
        task_id="run-csrf",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-csrf",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    user = _mapped_user(
        username="operator",
        password="password-1234",
        product_roles=["campaign-operator"],
        governance_identity="admin-a",
    )
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(user)
    response = csrf_client.post("/agent/runs/run-csrf/stop/", {"reason": "No CSRF token"})
    assert response.status_code == 403
