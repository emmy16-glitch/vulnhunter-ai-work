import json
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.security_tools.nuclei_activation import (
    EngagementAuthorization,
    NucleiCommandPlan,
    NucleiPlanApproval,
    validate_nuclei_target_scope,
)
from vulnhunter.security_tools.nuclei_execution import (
    DeterministicFakeRunner,
    DisabledNucleiRunner,
    DuplicateNucleiExecutionError,
    NucleiExecutionError,
    NucleiExecutionHarness,
    NucleiExecutionInvocation,
    NucleiExecutionRequest,
    NucleiExecutionStore,
    NucleiRuntimeReadiness,
    NucleiScannerAdapter,
)
from vulnhunter.security_tools.scanner_protocol import (
    PlannedScannerAdapter,
    ScannerAdapterDescriptor,
    ScannerAdapterRegistry,
    ScannerAdapterStatus,
    ScannerCandidateObservation,
    ScannerCompatibilityManifest,
    ScannerDeploymentMode,
    ScannerExecutionLimits,
    ScannerJobState,
    ScannerKind,
)
from vulnhunter.security_tools.scanner_worker import disabled_worker_status

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
TARGET = "https://lab.example:443/app"
ADDRESS = "93.184.216.34"
PROHIBITED = (
    "automatic-updates",
    "cloud-upload",
    "public-oast",
    "raw-command-arguments",
)


def _resolver(_hostname: str) -> tuple[str, ...]:
    return (ADDRESS,)


def _compatibility() -> ScannerCompatibilityManifest:
    root = Path(__file__).resolve().parents[2]
    return ScannerCompatibilityManifest.load(
        root / "config/security_tools/scanner_compatibility.json"
    )


def _authorization(**updates) -> EngagementAuthorization:
    values = {
        "authorization_id": "engagement-31",
        "target_owner": "Laboratory Owner",
        "approving_person": "Human Approver",
        "approved_targets": (TARGET,),
        "approved_addresses": (ADDRESS,),
        "approved_ports": (443,),
        "approved_protocols": ("https",),
        "approved_scan_profiles": ("passive", "standard", "intrusive", "retest"),
        "starts_at": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(hours=1),
        "private_network_approved": False,
        "prohibited_actions": PROHIBITED,
        "audit": {
            "recorded_at": NOW - timedelta(minutes=10),
            "recorded_by": "approver-31",
            "approval_basis": "Controlled local laboratory harness approval",
        },
    }
    values.update(updates)
    return EngagementAuthorization.issue(**values)


def _plan(tmp_path, *, authorization=None, expires_at=None, output_directory=None):
    authorization = authorization or _authorization()
    target = validate_nuclei_target_scope(
        TARGET,
        authorization=authorization,
        resolver=_resolver,
        now=NOW,
    )
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(exist_ok=True)
    output = output_directory or (evidence_root / "run-31")
    output.mkdir(exist_ok=True)
    plan = NucleiCommandPlan.create(
        authorization_id=authorization.authorization_id,
        exact_targets=(target,),
        exact_profile="passive",
        template_manifest_hashes=("a" * 64,),
        output_directory=output.resolve(),
        rate_limit=5,
        concurrency=2,
        expires_at=expires_at or (NOW + timedelta(minutes=20)),
        requires_isolation=False,
    )
    return authorization, plan, evidence_root.resolve()


def _approval(plan, **updates):
    values = {
        "approval_id": "approval-31",
        "authorization_id": plan.authorization_id,
        "command_plan_digest": plan.plan_digest,
        "approved_by": "Human Approver",
        "approved_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=10),
    }
    values.update(updates)
    return NucleiPlanApproval(**values)


def _limits(**updates):
    values = {
        "timeout_seconds": 300,
        "maximum_stdout_bytes": 1024,
        "maximum_stderr_bytes": 1024,
        "concurrency": 2,
        "rate_limit": 5,
        "termination_grace_seconds": 2,
    }
    values.update(updates)
    return ScannerExecutionLimits(**values)


def _bundle(tmp_path, *, runner=None, allow_test_runner=False, resolver=_resolver):
    authorization, plan, evidence_root = _plan(tmp_path)
    approval = _approval(plan)
    compatibility = _compatibility()
    request = NucleiExecutionRequest.from_plan(
        execution_id="execution-31",
        plan=plan,
        approval=approval,
        limits=_limits(),
        cancellation_id="cancel-31",
        correlation_id="correlation-31",
        compatibility_manifest_sha256=compatibility.fingerprint(),
    )
    readiness = NucleiRuntimeReadiness(
        engine_version="v3.8.0",
        template_release="v10.4.5",
        template_manifest_hashes=plan.template_manifest_hashes,
        compatibility_manifest_sha256=compatibility.fingerprint(),
        checked_at=NOW - timedelta(seconds=10),
    )
    store = NucleiExecutionStore(tmp_path / "execution-state")
    harness = NucleiExecutionHarness(
        store=store,
        runner=runner or DisabledNucleiRunner(),
        resolver=resolver,
        approved_output_root=evidence_root,
        compatibility_manifest=compatibility,
        allow_test_runner=allow_test_runner,
    )
    invocation = NucleiExecutionInvocation(
        request=request,
        plan=plan,
        approval=approval,
        authorization=authorization,
        readiness=readiness,
        actor_id="operator-31",
        now=NOW,
    )
    return harness, invocation


def _replace_invocation(invocation, **updates):
    values = invocation.model_dump()
    values.update(updates)
    return NucleiExecutionInvocation.model_validate(values)


def test_disabled_production_runner_creates_no_process_or_network_and_records_block(
    tmp_path, monkeypatch
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    harness, invocation = _bundle(tmp_path)

    record = harness.execute(invocation)

    assert record.state is ScannerJobState.BLOCKED_EXECUTION_DISABLED
    assert record.request.execution_enabled is False
    assert record.observations == ()
    assert len(record.evidence) == 1
    states = [event.new_state for event in harness.store.list_events("execution-31")]
    assert states == [
        ScannerJobState.PREPARED,
        ScannerJobState.VALIDATED,
        ScannerJobState.BLOCKED_EXECUTION_DISABLED,
    ]


@pytest.mark.parametrize(
    "field,value",
    [
        ("command", "nuclei -u https://example.test"),
        ("argv", ["nuclei", "-u", "https://example.test"]),
        ("environment", {"TOKEN": "secret"}),
        ("api_token", "secret"),
        ("execution_enabled", True),
    ],
)
def test_execution_request_rejects_command_argv_environment_secrets_and_enablement(
    tmp_path, field, value
):
    _, invocation = _bundle(tmp_path)
    payload = invocation.request.model_dump()
    payload[field] = value

    with pytest.raises(ValidationError):
        NucleiExecutionRequest.model_validate(payload)


def test_exact_plan_digest_is_required(tmp_path):
    harness, invocation = _bundle(tmp_path)
    request = invocation.request.model_copy(update={"plan_digest": "b" * 64})

    record = harness.execute(_replace_invocation(invocation, request=request))

    assert record.state is ScannerJobState.FAILED
    assert "exact command-plan digest" in harness.store.list_events("execution-31")[-1].reason


def test_mismatched_approval_is_rejected(tmp_path):
    harness, invocation = _bundle(tmp_path)
    approval = invocation.approval.model_copy(update={"approval_id": "approval-other"})

    record = harness.execute(_replace_invocation(invocation, approval=approval))

    assert record.state is ScannerJobState.FAILED
    assert "approval does not match" in harness.store.list_events("execution-31")[-1].reason


def test_expired_plan_is_rejected(tmp_path):
    authorization = _authorization()
    authorization, plan, evidence_root = _plan(
        tmp_path,
        authorization=authorization,
        expires_at=NOW - timedelta(seconds=1),
    )
    approval = _approval(plan)
    compatibility = _compatibility()
    request = NucleiExecutionRequest.from_plan(
        execution_id="expired-plan-31",
        plan=plan,
        approval=approval,
        limits=_limits(),
        cancellation_id="cancel-expired-plan",
        correlation_id="correlation-expired-plan",
        compatibility_manifest_sha256=compatibility.fingerprint(),
    )
    readiness = NucleiRuntimeReadiness(
        engine_version="v3.8.0",
        template_release="v10.4.5",
        template_manifest_hashes=plan.template_manifest_hashes,
        compatibility_manifest_sha256=compatibility.fingerprint(),
        checked_at=NOW - timedelta(seconds=10),
    )
    harness = NucleiExecutionHarness(
        store=NucleiExecutionStore(tmp_path / "state-expired-plan"),
        runner=DisabledNucleiRunner(),
        resolver=_resolver,
        approved_output_root=evidence_root,
        compatibility_manifest=compatibility,
    )

    record = harness.execute(
        NucleiExecutionInvocation(
            request=request,
            plan=plan,
            approval=approval,
            authorization=authorization,
            readiness=readiness,
            actor_id="operator-31",
            now=NOW,
        )
    )

    assert record.state is ScannerJobState.FAILED
    assert "expired" in harness.store.list_events(request.execution_id)[-1].reason


def test_expired_authorization_is_rejected(tmp_path):
    harness, invocation = _bundle(tmp_path)
    expired = _authorization(
        starts_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
        audit={
            "recorded_at": NOW - timedelta(hours=3),
            "recorded_by": "approver-31",
            "approval_basis": "Controlled local laboratory harness approval",
        },
    )

    record = harness.execute(_replace_invocation(invocation, authorization=expired))

    assert record.state is ScannerJobState.FAILED
    assert "not active" in harness.store.list_events("execution-31")[-1].reason


def test_altered_target_scope_is_rejected(tmp_path):
    harness, invocation = _bundle(tmp_path)
    changed_target = invocation.request.exact_targets[0].model_copy(
        update={"path": "/other", "url": "https://lab.example:443/other"}
    )
    request = invocation.request.model_copy(update={"exact_targets": (changed_target,)})

    record = harness.execute(_replace_invocation(invocation, request=request))

    assert record.state is ScannerJobState.FAILED
    assert "target scope differs" in harness.store.list_events("execution-31")[-1].reason


def test_changed_dns_resolution_is_rejected(tmp_path):
    harness, invocation = _bundle(
        tmp_path,
        resolver=lambda _hostname: ("93.184.216.35",),
    )

    record = harness.execute(invocation)

    assert record.state is ScannerJobState.FAILED
    assert "escaped the approved address" in harness.store.list_events("execution-31")[-1].reason


def test_changed_template_digest_is_rejected(tmp_path):
    harness, invocation = _bundle(tmp_path)
    readiness = invocation.readiness.model_copy(update={"template_manifest_hashes": ("b" * 64,)})

    record = harness.execute(_replace_invocation(invocation, readiness=readiness))

    assert record.state is ScannerJobState.FAILED
    assert "template hashes changed" in harness.store.list_events("execution-31")[-1].reason


@pytest.mark.parametrize(
    "readiness_update,message",
    [
        ({"engine_version": "v9.9.9"}, "engine version"),
        ({"template_release": "v0.0.1"}, "template release"),
        ({"checked_at": NOW - timedelta(hours=1)}, "stale"),
    ],
)
def test_readiness_version_and_freshness_mismatch_is_rejected(tmp_path, readiness_update, message):
    harness, invocation = _bundle(tmp_path)
    readiness = invocation.readiness.model_copy(update=readiness_update)

    record = harness.execute(_replace_invocation(invocation, readiness=readiness))

    assert record.state is ScannerJobState.FAILED
    assert message in harness.store.list_events("execution-31")[-1].reason


def test_unsafe_evidence_root_is_rejected(tmp_path):
    harness, invocation = _bundle(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    plan = NucleiCommandPlan.create(
        authorization_id=invocation.plan.authorization_id,
        exact_targets=invocation.plan.exact_targets,
        exact_profile=invocation.plan.exact_profile,
        template_manifest_hashes=invocation.plan.template_manifest_hashes,
        output_directory=outside.resolve(),
        rate_limit=invocation.plan.rate_limit,
        concurrency=invocation.plan.concurrency,
        expires_at=invocation.plan.expires_at,
        requires_isolation=False,
    )
    approval = _approval(plan)
    request = NucleiExecutionRequest.from_plan(
        execution_id="outside-evidence-31",
        plan=plan,
        approval=approval,
        limits=_limits(),
        cancellation_id="cancel-outside-evidence",
        correlation_id="correlation-outside-evidence",
        compatibility_manifest_sha256=harness.compatibility_manifest.fingerprint(),
    )
    readiness = invocation.readiness.model_copy(
        update={"template_manifest_hashes": plan.template_manifest_hashes}
    )

    record = harness.execute(
        _replace_invocation(
            invocation,
            request=request,
            plan=plan,
            approval=approval,
            readiness=readiness,
        )
    )

    assert record.state is ScannerJobState.FAILED
    assert "outside the approved root" in harness.store.list_events(request.execution_id)[-1].reason


def test_symlink_evidence_path_is_rejected(tmp_path):
    harness, invocation = _bundle(tmp_path)
    real = invocation.plan.output_directory
    link = real.parent / "linked-run"
    link.symlink_to(real, target_is_directory=True)
    plan = NucleiCommandPlan.create(
        authorization_id=invocation.plan.authorization_id,
        exact_targets=invocation.plan.exact_targets,
        exact_profile=invocation.plan.exact_profile,
        template_manifest_hashes=invocation.plan.template_manifest_hashes,
        output_directory=link.absolute(),
        rate_limit=invocation.plan.rate_limit,
        concurrency=invocation.plan.concurrency,
        expires_at=invocation.plan.expires_at,
        requires_isolation=False,
    )
    approval = _approval(plan)
    request = NucleiExecutionRequest.from_plan(
        execution_id="symlink-evidence-31",
        plan=plan,
        approval=approval,
        limits=_limits(),
        cancellation_id="cancel-symlink-evidence",
        correlation_id="correlation-symlink-evidence",
        compatibility_manifest_sha256=harness.compatibility_manifest.fingerprint(),
    )

    record = harness.execute(
        _replace_invocation(invocation, request=request, plan=plan, approval=approval)
    )

    assert record.state is ScannerJobState.FAILED
    assert "symlink" in harness.store.list_events(request.execution_id)[-1].reason


def test_duplicate_execution_id_is_rejected(tmp_path):
    harness, invocation = _bundle(tmp_path)
    harness.execute(invocation)

    with pytest.raises(DuplicateNucleiExecutionError):
        harness.execute(invocation)


def test_invalid_lifecycle_transition_is_rejected(tmp_path):
    _, invocation = _bundle(tmp_path)
    store = NucleiExecutionStore(tmp_path / "transition-state")
    store.prepare(invocation.request, actor_id="operator-31", now=NOW)

    with pytest.raises(NucleiExecutionError, match="invalid execution transition"):
        store.transition(
            invocation.request.execution_id,
            ScannerJobState.COMPLETED,
            actor_id="operator-31",
            reason="Invalid direct completion.",
            now=NOW,
        )


def test_fake_runner_success_path_and_candidate_only_observation(tmp_path):
    observation = ScannerCandidateObservation(
        observation_id="candidate-31",
        scanner_id="nuclei",
        target_reference=TARGET,
        title="Fake unverified observation",
        severity="low",
        confidence="candidate",
        metadata={"template_id": "reviewed-passive"},
    )
    runner = DeterministicFakeRunner(observations=(observation,))
    harness, invocation = _bundle(tmp_path, runner=runner, allow_test_runner=True)

    record = harness.execute(invocation)

    assert record.state is ScannerJobState.COMPLETED
    assert runner.calls == 1
    assert record.observations[0].finding_status == "candidate"
    assert [event.new_state for event in harness.store.list_events("execution-31")] == [
        ScannerJobState.PREPARED,
        ScannerJobState.VALIDATED,
        ScannerJobState.STARTING,
        ScannerJobState.RUNNING,
        ScannerJobState.COMPLETED,
    ]


def test_fake_runner_controlled_failure(tmp_path):
    harness, invocation = _bundle(
        tmp_path,
        runner=DeterministicFakeRunner(scenario="failure"),
        allow_test_runner=True,
    )

    assert harness.execute(invocation).state is ScannerJobState.FAILED


def test_fake_runner_deterministic_cancellation(tmp_path):
    harness, invocation = _bundle(
        tmp_path,
        runner=DeterministicFakeRunner(scenario="cancelled"),
        allow_test_runner=True,
    )

    assert harness.execute(invocation).state is ScannerJobState.CANCELLED


def test_cancellation_request_is_idempotent(tmp_path):
    _, invocation = _bundle(tmp_path)
    store = NucleiExecutionStore(tmp_path / "cancel-state")
    store.prepare(invocation.request, actor_id="operator-31", now=NOW)

    first = store.request_cancellation(
        invocation.request.execution_id,
        reason="Operator requested cancellation.",
        actor_id="operator-31",
        now=NOW,
    )
    second = store.request_cancellation(
        invocation.request.execution_id,
        reason="Repeated cancellation.",
        actor_id="operator-31",
        now=NOW + timedelta(seconds=1),
    )

    assert first.cancellation_requested is True
    assert second.last_transition_sha256 == first.last_transition_sha256
    assert second.cancellation_reason == first.cancellation_reason


def test_fake_runner_deterministic_timeout(tmp_path):
    harness, invocation = _bundle(
        tmp_path,
        runner=DeterministicFakeRunner(scenario="timed_out"),
        allow_test_runner=True,
    )

    assert harness.execute(invocation).state is ScannerJobState.TIMED_OUT


def test_stdout_and_stderr_are_independently_bounded_truncated_and_redacted(tmp_path):
    secret = "Bearer unit-test-secret-value"
    runner = DeterministicFakeRunner(
        stdout=secret + "\n" + ("A" * 5000),
        stderr=secret + "\n" + ("B" * 5000),
    )
    harness, invocation = _bundle(tmp_path, runner=runner, allow_test_runner=True)

    record = harness.execute(invocation)

    assert record.stdout is not None and record.stderr is not None
    assert record.stdout.captured_bytes == 1024
    assert record.stderr.captured_bytes == 1024
    assert record.stdout.truncated is True
    assert record.stderr.truncated is True
    assert "unit-test-secret-value" not in record.stdout.text
    assert "unit-test-secret-value" not in record.stderr.text


def test_non_candidate_observation_status_is_rejected():
    with pytest.raises(ValidationError):
        ScannerCandidateObservation(
            observation_id="observation-31",
            scanner_id="nuclei",
            target_reference=TARGET,
            title="Invalid confirmed observation",
            severity="high",
            confidence="confirmed",
            finding_status="confirmed",
        )


def test_unfinished_state_recovery_fails_closed(tmp_path):
    _, invocation = _bundle(tmp_path)
    store = NucleiExecutionStore(tmp_path / "recovery-state")
    store.prepare(invocation.request, actor_id="operator-31", now=NOW)

    recovered = store.recover_unfinished(actor_id="recovery-31", now=NOW + timedelta(seconds=1))

    assert recovered[0].state is ScannerJobState.BLOCKED_EXECUTION_DISABLED


def test_scanner_protocol_registers_nuclei_and_mobile_under_one_interface(tmp_path):
    harness, _ = _bundle(tmp_path)
    registry = ScannerAdapterRegistry(
        [
            NucleiScannerAdapter(harness),
            PlannedScannerAdapter(
                ScannerAdapterDescriptor(
                    adapter_id="mobile-analysis-planned-adapter",
                    scanner_kind=ScannerKind.MOBILE_ANALYSIS,
                    status=ScannerAdapterStatus.PLANNED,
                    deployment_mode=ScannerDeploymentMode.DISABLED,
                )
            ),
        ]
    )

    assert [item.scanner_kind for item in registry.descriptors()] == [
        ScannerKind.MOBILE_ANALYSIS,
        ScannerKind.NUCLEI,
    ]


def test_compatibility_manifest_tracks_versions_feeds_checksums_and_deployment():
    root = Path(__file__).resolve().parents[2]
    manifest = _compatibility()

    manifest.verify_repository_manifests(root)
    nuclei = manifest.get("nuclei")
    assert nuclei.version_pin.engine_version == "v3.8.0"
    assert nuclei.version_pin.feed is not None
    assert nuclei.version_pin.feed.release == "v10.4.5"
    assert nuclei.version_pin.feed.manifest_sha256
    assert nuclei.descriptor.deployment_mode is ScannerDeploymentMode.ISOLATED_CONTAINER
    assert {record.version_pin.scanner_id for record in manifest.records} == {
        "nuclei",
        "mobile_analysis",
    }


def test_disabled_worker_boundary_starts_no_listener_or_scanner_process():
    root = Path(__file__).resolve().parents[2]

    status = disabled_worker_status(root)

    assert status["execution_enabled"] is False
    assert status["network_listener_started"] is False
    assert status["scanner_process_started"] is False
    assert status["worker_state"] == "blocked_execution_disabled"


def test_persisted_execution_record_contains_no_command_argv_or_environment(tmp_path):
    harness, invocation = _bundle(tmp_path)
    record = harness.execute(invocation)
    payload = json.loads(
        (harness.store.records / f"{record.request.execution_id}.json").read_text(encoding="utf-8")
    )
    serialized = json.dumps(payload, sort_keys=True)

    assert '"command"' not in serialized
    assert '"argv"' not in serialized
    assert '"environment"' not in serialized
    assert '"api_token"' not in serialized
    assert payload["request"]["execution_enabled"] is False


def test_persisted_cancellation_reaches_cooperative_runner_checkpoint(tmp_path):
    class CheckpointRunner:
        is_test_double = True

        def __init__(self):
            self.cancel_callback = None

        def run(self, specification, *, control):
            del specification
            assert self.cancel_callback is not None
            self.cancel_callback()
            control.checkpoint()
            raise AssertionError("checkpoint must raise after persisted cancellation")

    runner = CheckpointRunner()
    harness, invocation = _bundle(tmp_path, runner=runner, allow_test_runner=True)
    runner.cancel_callback = lambda: harness.request_cancellation(
        invocation.request.execution_id,
        reason="Operator requested cooperative cancellation.",
        actor_id="operator-31",
        now=NOW,
    )

    record = harness.execute(invocation)

    assert record.state is ScannerJobState.CANCELLED
    assert ScannerJobState.CANCELLING in [
        event.new_state for event in harness.store.list_events(invocation.request.execution_id)
    ]


def test_monotonic_deadline_reaches_timeout_without_sleeping(tmp_path):
    class CheckpointRunner:
        is_test_double = True

        def run(self, specification, *, control):
            del specification
            control.checkpoint()
            raise AssertionError("checkpoint must raise after the deadline")

    moments = iter((100.0, 401.0))
    harness, invocation = _bundle(
        tmp_path,
        runner=CheckpointRunner(),
        allow_test_runner=True,
    )
    harness.monotonic = lambda: next(moments)

    record = harness.execute(invocation)

    assert record.state is ScannerJobState.TIMED_OUT
