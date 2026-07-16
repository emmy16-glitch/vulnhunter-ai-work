from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.actions import ActionClass, ActionManifest, ExecutionLimits
from vulnhunter.approvals import (
    ApprovalConditionEvaluation,
    ApprovalConditionEvaluator,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalStore,
    CanonicalApprovalExecutionPlan,
)
from vulnhunter.approvals.store import ApprovalConflictError

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _manifest(**updates) -> ActionManifest:
    values = {
        "manifest_id": "manifest-01",
        "campaign_id": "campaign-01",
        "requested_by": "requester-01",
        "role_id": "operator-01",
        "skill_id": "safe-assessment",
        "action": "tool.run",
        "action_class": ActionClass.CONSEQUENTIAL,
        "tool_id": "nmap",
        "operation": "safe-discovery",
        "target_references": ("target-01",),
        "authorization_references": ("authorization-01",),
        "limits": ExecutionLimits(
            timeout_seconds=60,
            maximum_requests=20,
            maximum_output_bytes=4096,
        ),
        "approval_required": True,
        "created_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
        "purpose": "Run one bounded laboratory assessment.",
    }
    values.update(updates)
    return ActionManifest(**values)


def _plan(manifest: ActionManifest, **updates) -> CanonicalApprovalExecutionPlan:
    values = {
        "execution_id": "execution-01",
        "action_manifest_sha256": manifest.fingerprint(),
        "target_identifiers": manifest.target_references,
        "selected_tool": manifest.tool_id,
        "selected_profile": "safe-assessment",
        "request_budget": 10,
        "runtime_budget_seconds": 30,
        "output_budget_bytes": 2048,
        "filesystem_paths": (),
        "network_destinations": ("127.0.0.1:8080",),
        "adapter_identity": "nmap-safe-adapter",
    }
    values.update(updates)
    return CanonicalApprovalExecutionPlan(**values)


def _request(manifest: ActionManifest, request_id: str) -> ApprovalRequest:
    return ApprovalRequest(
        request_id=request_id,
        campaign_id=manifest.campaign_id,
        run_id="run-01",
        action_manifest_sha256=manifest.fingerprint(),
        requested_by=manifest.requested_by,
        summary="Run bounded assessment.",
        risk_summary="Consequential tool execution.",
        requested_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _approved(
    store: ApprovalStore,
    manifest: ActionManifest,
    *,
    request_id: str = "approval-conditional",
    conditions: tuple[str, ...] = ("maximum_requests=10",),
) -> ApprovalRequest:
    store.create(_request(manifest, request_id))
    return store.decide(
        request_id=request_id,
        actor_id="approver-01",
        decision=ApprovalDecision.APPROVE_WITH_CONDITIONS,
        reason="Approve only with exact bounded limits.",
        conditions=conditions,
        now=NOW + timedelta(minutes=1),
    )


def _consume(
    store: ApprovalStore,
    approval: ApprovalRequest,
    manifest: ActionManifest,
    plan: CanonicalApprovalExecutionPlan,
    *,
    actor_id: str = "runtime-01",
):
    return store.consume(
        request_id=approval.request_id,
        action_manifest_sha256=manifest.fingerprint(),
        execution_id="execution-01",
        actor_id=actor_id,
        now=NOW + timedelta(minutes=2),
        manifest=manifest,
        execution_plan=plan,
    )


class ForgingEvaluator(ApprovalConditionEvaluator):
    def __init__(self, mutation):
        super().__init__()
        self.mutation = mutation

    def evaluate(self, **kwargs) -> ApprovalConditionEvaluation:
        evaluation = super().evaluate(**kwargs)
        return self.mutation(evaluation)


def test_caller_supplied_typed_evaluation_cannot_consume_approval(tmp_path):
    manifest = _manifest()
    store = ApprovalStore(tmp_path / "approvals.db")
    approval = _approved(store, manifest)

    with pytest.raises(TypeError):
        store.consume(
            request_id=approval.request_id,
            action_manifest_sha256=manifest.fingerprint(),
            execution_id="execution-01",
            actor_id="runtime-01",
            manifest=manifest,
            execution_plan=_plan(manifest),
            condition_evaluation=object(),
        )


@pytest.mark.parametrize(
    ("field", "actual", "forged", "condition"),
    [
        ("maximum_requests", 11, 10, "maximum_requests=10"),
        ("maximum_runtime_seconds", 31, 30, "maximum_runtime_seconds=30"),
        ("maximum_output_bytes", 2049, 2048, "maximum_output_bytes=2048"),
    ],
)
def test_forged_budget_understatement_is_rejected(tmp_path, field, actual, forged, condition):
    manifest = _manifest()
    plan_fields = {
        "maximum_requests": "request_budget",
        "maximum_runtime_seconds": "runtime_budget_seconds",
        "maximum_output_bytes": "output_budget_bytes",
    }

    def understate(evaluation):
        facts = evaluation.evaluated_facts.model_copy(update={field: forged})
        return evaluation.model_copy(update={"evaluated_facts": facts})

    store = ApprovalStore(
        tmp_path / "approvals.db",
        condition_evaluator=ForgingEvaluator(understate),
    )
    approval = _approved(store, manifest, conditions=(condition,))

    with pytest.raises(ApprovalConflictError, match="not satisfied"):
        _consume(store, approval, manifest, _plan(manifest, **{plan_fields[field]: actual}))


@pytest.mark.parametrize(
    ("plan_field", "fact_field", "condition"),
    [
        ("credential_attempts", "credential_attempts", "no_credential_attempts=true"),
        ("destructive_checks", "destructive_checks", "no_destructive_checks=true"),
    ],
)
def test_forged_safe_action_assertion_is_rejected(tmp_path, plan_field, fact_field, condition):
    manifest = _manifest()

    def falsify(evaluation):
        facts = evaluation.evaluated_facts.model_copy(update={fact_field: False})
        return evaluation.model_copy(update={"evaluated_facts": facts})

    store = ApprovalStore(
        tmp_path / "approvals.db",
        condition_evaluator=ForgingEvaluator(falsify),
    )
    approval = _approved(store, manifest, conditions=(condition,))

    with pytest.raises(ApprovalConflictError, match="not satisfied"):
        _consume(store, approval, manifest, _plan(manifest, **{plan_field: True}))


def test_another_manifest_binding_is_rejected(tmp_path):
    manifest = _manifest()
    other = _manifest(manifest_id="manifest-02")
    store = ApprovalStore(tmp_path / "approvals.db")
    approval = _approved(store, manifest)

    with pytest.raises(ApprovalConflictError, match="not satisfied"):
        _consume(
            store, approval, manifest, _plan(manifest, action_manifest_sha256=other.fingerprint())
        )


def test_another_execution_binding_is_rejected(tmp_path):
    manifest = _manifest()
    store = ApprovalStore(tmp_path / "approvals.db")
    approval = _approved(store, manifest)

    with pytest.raises(ApprovalConflictError, match="not satisfied"):
        _consume(store, approval, manifest, _plan(manifest, execution_id="execution-02"))


def test_another_execution_plan_hash_is_rejected(tmp_path):
    manifest = _manifest()

    def change_plan_hash(evaluation):
        return evaluation.model_copy(update={"execution_plan_sha256": "f" * 64})

    store = ApprovalStore(
        tmp_path / "approvals.db",
        condition_evaluator=ForgingEvaluator(change_plan_hash),
    )
    approval = _approved(store, manifest)

    with pytest.raises(ApprovalConflictError, match="not satisfied"):
        _consume(store, approval, manifest, _plan(manifest))


def test_stale_evaluation_is_rejected(tmp_path):
    manifest = _manifest()

    def make_stale(evaluation):
        return evaluation.model_copy(
            update={
                "evaluated_at": NOW,
                "expires_at": NOW + timedelta(seconds=30),
            }
        )

    store = ApprovalStore(
        tmp_path / "approvals.db",
        condition_evaluator=ForgingEvaluator(make_stale),
    )
    approval = _approved(store, manifest)

    with pytest.raises(ApprovalConflictError, match="not satisfied"):
        _consume(store, approval, manifest, _plan(manifest))


def test_correct_authoritative_evaluation_allows_exactly_one_consumption(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    manifest = _manifest()
    store = ApprovalStore(tmp_path / "approvals.db")
    approval = _approved(
        store,
        manifest,
        conditions=(
            "maximum_requests=10",
            "maximum_runtime_seconds=30",
            "maximum_output_bytes=2048",
            "permitted_target_id=target-01",
            "permitted_tool=nmap",
            "permitted_profile=safe-assessment",
            f"permitted_filesystem_path={allowed}",
            "permitted_network_destination=127.0.0.1:8080",
            "permitted_adapter=nmap-safe-adapter",
            "no_credential_attempts=true",
            "no_destructive_checks=true",
        ),
    )
    plan = _plan(manifest, filesystem_paths=(allowed / "result.json",))

    consumed = _consume(store, approval, manifest, plan)

    assert consumed.status == ApprovalStatus.CONSUMED
    assert "condition_evaluation_sha256" in store.events(approval.request_id)[-1].detail
    with pytest.raises(ApprovalConflictError, match="not active"):
        _consume(store, approval, manifest, plan)


def test_requester_self_consumption_remains_rejected(tmp_path):
    manifest = _manifest()
    store = ApprovalStore(tmp_path / "approvals.db")
    approval = _approved(store, manifest)

    with pytest.raises(ApprovalConflictError, match="requester cannot consume"):
        _consume(
            store,
            approval,
            manifest,
            _plan(manifest),
            actor_id=manifest.requested_by,
        )


def test_missing_and_unsupported_canonical_conditions_fail_closed(tmp_path):
    manifest = _manifest()
    store = ApprovalStore(tmp_path / "approvals.db")
    missing = _approved(store, manifest, request_id="approval-missing")
    with pytest.raises(ApprovalConflictError, match="canonical execution inputs"):
        store.consume(
            request_id=missing.request_id,
            action_manifest_sha256=manifest.fingerprint(),
            execution_id="execution-01",
            actor_id="runtime-01",
            now=NOW + timedelta(minutes=2),
        )

    unsupported = _approved(
        store,
        manifest,
        request_id="approval-unsupported",
        conditions=("unverifiable=true",),
    )
    with pytest.raises(ApprovalConflictError, match="not satisfied"):
        _consume(store, unsupported, manifest, _plan(manifest))
