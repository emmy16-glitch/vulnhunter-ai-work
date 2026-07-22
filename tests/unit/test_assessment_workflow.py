from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnhunter.agent.controller import AgentController, AgentRuntime
from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import RuntimeConfig
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent.tools import ToolRegistry
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.approvals import ApprovalDecision, ApprovalStore
from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.evidence import EvidenceStore, FindingStatus
from vulnhunter.product.service import ProductApplicationService, ProductPaths
from vulnhunter.scope import ApprovedTarget
from vulnhunter.security_tools.nuclei_activation import NucleiTemplateManifest
from vulnhunter.web.assessment_workflow import (
    AssessmentWorkflowError,
    AssessmentWorkflowService,
    bind_nuclei_authorization,
)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
ADDRESS = "10.20.30.40"
TARGET = "https://private.lab:443/app"


def _record(
    store: AuthorizationStore,
    *,
    owner: str = "operator-a",
    expires_at: datetime | None = None,
):
    return issue_authorization(
        store,
        ApprovedTarget(
            original_url=TARGET,
            normalized_url=TARGET,
            scheme="https",
            hostname="private.lab",
            port=443,
            path="/app",
            resolved_addresses=(ADDRESS,),
        ),
        owner=owner,
        approved_by="approver-a",
        purpose="Controlled private laboratory assessment.",
        expires_at=expires_at or NOW + timedelta(hours=2),
        limits=AuthorizationLimits(
            maximum_pages=10,
            maximum_depth=2,
            maximum_requests=20,
            minimum_request_delay_seconds=1,
        ),
        now=NOW - timedelta(minutes=10),
    )


def _service(tmp_path: Path, *, ready: bool = True) -> AssessmentWorkflowService:
    authorization_store = AuthorizationStore.from_path(tmp_path / "authorization.db")
    authorization_store.initialize()
    template_root = tmp_path / "templates"
    template_root.mkdir()
    template = template_root / "passive.yaml"
    template.write_text("id: reviewed-passive\ninfo:\n  name: Reviewed passive\n", encoding="utf-8")
    manifest = NucleiTemplateManifest.model_validate(
        {
            "template_release": "v10.4.5",
            "entries": [
                {
                    "template_id": "reviewed-passive",
                    "relative_path": "passive.yaml",
                    "sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
                    "template_release": "v10.4.5",
                    "risk_class": "passive",
                    "required_approval_level": "reviewed",
                    "enabled": True,
                    "reviewed_by": "reviewer-a",
                    "reviewed_at": NOW - timedelta(days=1),
                }
            ],
        }
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    readiness = {
        "ready": ready,
        "installed": ready,
        "expected_engine": "v3.8.0",
        "expected_templates": "v10.4.5",
        "engine_pin_matches": ready,
        "templates_pin_matches": ready,
        "execution_enabled": ready,
        "reason": "Pinned local readiness is unavailable." if not ready else "Pins verified.",
    }
    readiness_path = tmp_path / "readiness.json"
    readiness_path.write_text(json.dumps(readiness), encoding="utf-8")
    return AssessmentWorkflowService(
        authorization_store=authorization_store,
        agent_store=AgentStore(tmp_path / "agent.db"),
        approval_store=ApprovalStore(tmp_path / "approvals.db"),
        activity_service=AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity")),
        profile_config=Path("config/security_tools/nuclei_profiles.json"),
        template_manifest=manifest_path,
        template_root=template_root,
        evidence_root=tmp_path / "evidence",
        readiness_report=readiness_path,
        clock=lambda: NOW,
    )


def _bind(service: AssessmentWorkflowService, record, *, profiles=("passive",)):
    return bind_nuclei_authorization(
        service.authorization_store,
        authorization_id=record.authorization_id,
        approved_profiles=profiles,
        private_network_approved=True,
        recorded_by="approver-a",
        approval_basis="Explicit controlled private-laboratory Nuclei planning approval.",
        now=NOW,
    )


def test_active_authorizations_are_identity_bound_and_expired_records_are_excluded(tmp_path):
    service = _service(tmp_path)
    owned = _record(service.authorization_store)
    other = _record(service.authorization_store, owner="operator-b")
    expired = _record(
        service.authorization_store,
        expires_at=NOW - timedelta(minutes=1),
    )
    _bind(service, owned)
    _bind(service, other)
    with pytest.raises(AssessmentWorkflowError, match="expired authorization"):
        _bind(service, expired)

    choices = service.list_authorizations(identity_id="operator-a", username="web-a")

    assert [choice.authorization_id for choice in choices] == [owned.authorization_id]
    assert choices[0].approved_targets == (TARGET,)
    assert choices[0].approved_profiles == ("passive",)


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"target": "https://other.lab:443/app"}, "not exactly authorized"),
        ({"target": "https://10.20.30.41:443/app"}, "not exactly authorized"),
        ({"port": 444}, "protocol or port"),
        ({"protocol": "http"}, "protocol or port"),
        ({"profile": "intrusive"}, "profile is not authorized"),
    ),
)
def test_browser_modified_scope_and_profile_values_are_rejected(tmp_path, updates, message):
    service = _service(tmp_path)
    record = _record(service.authorization_store)
    _bind(service, record)
    values = {
        "authorization_id": record.authorization_id,
        "target": TARGET,
        "protocol": "https",
        "port": 443,
        "profile": "passive",
        "identity_id": "operator-a",
        "username": "web-a",
    }
    values.update(updates)

    with pytest.raises(AssessmentWorkflowError, match=message):
        service.create_assessment(**values)

    assert service.agent_store.list_tasks() == ()


def test_creation_builds_exact_plan_and_never_starts_process_or_network(tmp_path):
    service = _service(tmp_path)
    record = _record(service.authorization_store)
    _bind(service, record)
    resolver_calls: list[str] = []

    def resolver(hostname: str):
        resolver_calls.append(hostname)
        return (ADDRESS,)

    with (
        patch("subprocess.run", side_effect=AssertionError("process start forbidden")),
        patch("subprocess.Popen", side_effect=AssertionError("process start forbidden")),
        patch("socket.getaddrinfo", side_effect=AssertionError("network DNS forbidden")),
    ):
        result = service.create_assessment(
            authorization_id=record.authorization_id,
            target=TARGET,
            protocol="https",
            port=443,
            profile="passive",
            identity_id="operator-a",
            username="web-a",
            resolver=resolver,
        )

    workflow = result.task.memory["assessment_workflow"]
    plan = workflow["command_plan"]
    assert resolver_calls == ["private.lab"]
    assert result.task.status.value == "paused_approval"
    assert result.approval_request is not None
    assert result.approval_request.action_manifest_sha256 == plan["plan_digest"]
    assert plan["exact_targets"][0]["url"] == TARGET
    assert plan["exact_profile"] == "passive"
    assert "argv" not in plan
    assert "command" not in plan
    assert workflow["execution_enabled"] is True


def test_changed_plan_digest_is_rejected_and_approved_plan_stays_execution_blocked(tmp_path):
    service = _service(tmp_path)
    record = _record(service.authorization_store)
    _bind(service, record)
    result = service.create_assessment(
        authorization_id=record.authorization_id,
        target=TARGET,
        protocol="https",
        port=443,
        profile="passive",
        identity_id="operator-a",
        username="web-a",
    )
    assert result.approval_request is not None
    with pytest.raises(AssessmentWorkflowError, match="current plan digest"):
        service.validate_approval_binding(
            request=result.approval_request,
            submitted_plan_digest="f" * 64,
        )

    approved = service.approval_store.decide(
        request_id=result.approval_request.request_id,
        actor_id="approver-b",
        decision=ApprovalDecision.APPROVE_ONCE,
        reason="Exact digest and scope were independently checked.",
        now=NOW + timedelta(seconds=1),
    )
    updated = service.record_approval_decision(request=approved, actor_id="approver-b")

    assert updated is not None
    assert updated.status.value == "blocked"
    assert updated.memory["assessment_workflow"]["workflow_state"] == "execution_blocked"
    assert updated.memory["assessment_workflow"]["execution_enabled"] is True


def test_readiness_false_records_blocked_state_without_an_approval(tmp_path):
    service = _service(tmp_path, ready=False)
    record = _record(service.authorization_store)
    _bind(service, record)

    result = service.create_assessment(
        authorization_id=record.authorization_id,
        target=TARGET,
        protocol="https",
        port=443,
        profile="passive",
        identity_id="operator-a",
        username="web-a",
    )

    assert result.task.status.value == "blocked"
    assert result.approval_request is None
    assert result.task.memory["assessment_workflow"]["workflow_state"] == "readiness_blocked"
    assert service.approval_store.list() == ()


def test_assessment_cancellation_and_timeout_project_into_workflow_state(tmp_path):
    service = _service(tmp_path)
    record = _record(service.authorization_store)
    _bind(service, record)

    def create():
        return service.create_assessment(
            authorization_id=record.authorization_id,
            target=TARGET,
            protocol="https",
            port=443,
            profile="passive",
            identity_id="operator-a",
            username="web-a",
        ).task

    cancelled_source = create()

    class NeverPlanner:
        def propose(self, task, events, tools):  # pragma: no cover - deadline wins
            raise AssertionError("planner must not run after deadline")

    controller = AgentController(
        AgentRuntime(
            config=RuntimeConfig(),
            store=service.agent_store,
            planner=NeverPlanner(),
            tools=ToolRegistry(),
            evaluator=ResultEvaluator(),
            activity_service=service.activity_service,
            clock=lambda: NOW + timedelta(days=2),
        )
    )
    cancelled = controller.cancel(cancelled_source.task_id, "Operator cancellation requested.")
    timed_out_source = create()
    timed_out = controller.run(timed_out_source.task_id)

    assert cancelled.status.value == "cancelled"
    assert cancelled.memory["assessment_workflow"]["workflow_state"] == "cancelled"
    assert timed_out.status.value == "timed_out"
    assert timed_out.memory["assessment_workflow"]["workflow_state"] == "timed_out"
    assert all(
        task.memory["assessment_workflow"]["execution_enabled"] is True
        for task in (cancelled, timed_out)
    )


def test_persisted_nuclei_observation_remains_candidate_and_artifact_is_real(tmp_path):
    service = _service(tmp_path)
    record = _record(service.authorization_store)
    _bind(service, record)
    result = service.create_assessment(
        authorization_id=record.authorization_id,
        target=TARGET,
        protocol="https",
        port=443,
        profile="passive",
        identity_id="operator-a",
        username="web-a",
    )
    workflow = result.task.memory["assessment_workflow"]
    artifact = service.evidence_root / result.task.task_id / "candidate.json"
    artifact.write_text('{"template_id": "reviewed-passive"}\n', encoding="utf-8")
    EvidenceStore(service.evidence_root).append(
        evidence_id="candidate-one",
        campaign_id="assessment-one",
        run_id=result.task.task_id,
        action_manifest_sha256=workflow["plan_digest"],
        tool_id="nuclei",
        target_reference=TARGET,
        finding_status=FindingStatus.CANDIDATE,
        title="Unverified Nuclei observation",
        severity="low",
        confidence="candidate",
        recorded_by="normalizer-a",
        artifact_path=artifact,
    )
    product = ProductApplicationService(
        ProductPaths(
            agent_database=tmp_path / "agent.db",
            evidence_root=service.evidence_root,
        )
    )

    detail = product.get_agent_run(result.task.task_id)

    assert detail.findings[0]["verification"] == "candidate"
    assert detail.findings[0]["verification"] not in {"human_confirmed", "published"}
    assert detail.artifacts[0]["filename"] == "candidate.json"
    assert detail.artifacts[0]["size"] == artifact.stat().st_size


def test_binding_event_preserves_nested_integrity_digests(tmp_path):
    from vulnhunter.security_tools.nuclei_activation import EngagementAuthorization

    service = _service(tmp_path)
    record = _record(service.authorization_store)
    engagement = _bind(service, record)

    events = [
        event
        for event in service.authorization_store.list_events(record.authorization_id)
        if event.event_type == "nuclei_activation_bound"
    ]

    assert len(events) == 1

    detail = events[0].detail
    stored_engagement = detail["engagement_record"]
    stored_audit = stored_engagement["audit"]

    assert detail["source_record_sha256"] == record.record_sha256
    assert stored_audit["previous_record_sha256"] == record.record_sha256
    assert stored_audit["record_sha256"] == engagement.audit.record_sha256

    EngagementAuthorization.model_validate(stored_engagement)


def test_redaction_preserves_payment_like_authorization_id():
    from vulnhunter.authorization.store import _redact_authorization_event_detail

    authorization_id = "auth-7028440521694474ae92"
    original = {
        "engagement_record": {
            "authorization_id": authorization_id,
        },
        "untrusted_note": "4111111111111111",
    }

    redacted = _redact_authorization_event_detail(original)

    assert redacted["engagement_record"]["authorization_id"] == authorization_id
    assert redacted["untrusted_note"] != original["untrusted_note"]
