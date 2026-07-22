import json
import os
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.agent.models import AgentTask, PermissionManifest, TaskStatus, ToolRisk
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.evidence.store import EvidenceStore
from vulnhunter.mobile import MobileArtifactIngestor
from vulnhunter.mobile.static_worker import MobileStaticWorker, MobileStaticWorkerPolicy
from vulnhunter.oracle.store import OracleStore
from vulnhunter.security_tools.nuclei_activation import (
    EngagementAuthorization,
    NucleiCommandPlan,
    NucleiPlanApproval,
    NucleiTemplateManifest,
    validate_nuclei_target_scope,
)
from vulnhunter.security_tools.nuclei_execution import (
    NucleiExecutionInvocation,
    NucleiExecutionRequest,
    NucleiExecutionStore,
    NucleiRuntimeReadiness,
)
from vulnhunter.security_tools.nuclei_pilot_service import NucleiPilotWorkerService
from vulnhunter.security_tools.nuclei_worker_pilot import NucleiPilotPolicy
from vulnhunter.security_tools.scanner_protocol import (
    ScannerCompatibilityManifest,
    ScannerExecutionLimits,
    ScannerJobState,
)
from vulnhunter.security_tools.worker_spool import (
    SignedNucleiWorkerJob,
    SignedWorkerSpool,
    WorkerSpoolError,
)

NOW = datetime(2026, 7, 18, 1, 0, tzinfo=UTC)
TARGET = "http://10.23.0.15:8080/"
ADDRESS = "10.23.0.15"


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _compatibility() -> ScannerCompatibilityManifest:
    root = _repository_root()
    manifest = ScannerCompatibilityManifest.load(
        root / "config/security_tools/scanner_compatibility.json"
    )
    manifest.verify_repository_manifests(root)
    return manifest


def _template_manifest() -> NucleiTemplateManifest:
    return NucleiTemplateManifest.model_validate_json(
        (_repository_root() / "config/security_tools/nuclei_template_manifest.json").read_text(
            encoding="utf-8"
        )
    )


def _invocation(tmp_path: Path) -> NucleiExecutionInvocation:
    authorization = EngagementAuthorization.issue(
        authorization_id="engagement-pilot",
        target_owner="Private Lab Owner",
        approving_person="Human Approver",
        approved_targets=(TARGET,),
        approved_addresses=(ADDRESS,),
        approved_ports=(8080,),
        approved_protocols=("http",),
        approved_scan_profiles=("passive",),
        starts_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        private_network_approved=True,
        prohibited_actions=(
            "automatic-updates",
            "cloud-upload",
            "public-oast",
            "raw-command-arguments",
        ),
        audit={
            "recorded_at": NOW - timedelta(minutes=10),
            "recorded_by": "approver-pilot",
            "approval_basis": "Passive private laboratory worker acceptance test",
        },
    )
    target = validate_nuclei_target_scope(
        TARGET,
        authorization=authorization,
        resolver=lambda _hostname: (ADDRESS,),
        now=NOW,
    )
    output_root = tmp_path / "evidence"
    output_root.mkdir()
    output = output_root / "assessment-pilot"
    output.mkdir()
    template_hash = _template_manifest().entries[0].fingerprint()
    plan = NucleiCommandPlan.create(
        authorization_id=authorization.authorization_id,
        exact_targets=(target,),
        exact_profile="passive",
        template_manifest_hashes=(template_hash,),
        output_directory=output.resolve(),
        rate_limit=1,
        concurrency=1,
        expires_at=NOW + timedelta(minutes=15),
        requires_isolation=False,
    )
    approval = NucleiPlanApproval(
        approval_id="approval-pilot",
        authorization_id=authorization.authorization_id,
        command_plan_digest=plan.plan_digest,
        approved_by="human-approver",
        approved_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    compatibility = _compatibility()
    request = NucleiExecutionRequest.from_plan(
        execution_id="execution-pilot",
        plan=plan,
        approval=approval,
        limits=ScannerExecutionLimits(
            timeout_seconds=30,
            maximum_stdout_bytes=64_000,
            maximum_stderr_bytes=64_000,
            concurrency=1,
            rate_limit=1,
            termination_grace_seconds=1,
        ),
        cancellation_id="cancel-pilot",
        correlation_id="assessment-pilot",
        compatibility_manifest_sha256=compatibility.fingerprint(),
    )
    readiness = NucleiRuntimeReadiness(
        engine_version="v3.8.0",
        template_release="v10.4.5",
        template_manifest_hashes=plan.template_manifest_hashes,
        compatibility_manifest_sha256=compatibility.fingerprint(),
        checked_at=NOW - timedelta(seconds=10),
    )
    return NucleiExecutionInvocation(
        request=request,
        plan=plan,
        approval=approval,
        authorization=authorization,
        readiness=readiness,
        actor_id="operator-pilot",
        now=NOW,
    )


def _fake_nuclei(path: Path) -> Path:
    script = path / "nuclei"
    payload = {
        "template-id": "vulnhunter-passive-security-headers",
        "matched-at": TARGET,
        "type": "http",
        "info": {"name": "Passive Security Header Review", "severity": "info"},
    }
    output = json.dumps(payload, separators=(",", ":"))
    script.write_text(
        "#!/bin/sh\n" + "printf '%s\n' " + json.dumps(output) + "\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    return script


def _task_store(tmp_path: Path, invocation: NucleiExecutionInvocation) -> AgentStore:
    store = AgentStore(tmp_path / "agent.db")
    store.create_task(
        AgentTask(
            task_id="assessment-pilot",
            objective="Run one passive private-lab worker acceptance test.",
            status=TaskStatus.RUNNING,
            permission_manifest=PermissionManifest(
                manifest_id="manifest-pilot",
                role_id="scanner-evidence-specialist",
                skill_id="governed-security-tool-operation",
                allowed_actions=("security_tool.nuclei.run",),
                allowed_tools=("nuclei",),
                allowed_risks=(ToolRisk.NETWORK,),
                allow_network=True,
            ),
            memory={
                "assessment_workflow": {
                    "workflow_state": "queued",
                    "command_plan": invocation.plan.model_dump(mode="json"),
                    "execution_id": invocation.request.execution_id,
                    "execution_enabled": False,
                }
            },
        )
    )
    return store


def test_signed_spool_rejects_tampering_and_replay(tmp_path):
    invocation = _invocation(tmp_path)
    key = b"k" * 32
    spool = SignedWorkerSpool(tmp_path / "spool")
    job = SignedNucleiWorkerJob.create(
        job_id="assessment-pilot",
        invocation=invocation,
        key=key,
        created_at=NOW,
    )
    path = spool.enqueue(job)
    with pytest.raises(WorkerSpoolError, match="already exists"):
        spool.enqueue(job)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["invocation"]["actor_id"] = "tampered-actor"
    path.write_text(json.dumps(payload), encoding="utf-8")
    claimed = spool.claim_next()
    assert claimed is not None
    with pytest.raises(WorkerSpoolError, match="invalid|signature"):
        spool.load_claimed(claimed, key=key, now=NOW + timedelta(seconds=1))


def test_passive_private_lab_worker_runs_and_creates_one_unified_finding(tmp_path):
    invocation = _invocation(tmp_path)
    key = b"s" * 32
    spool = SignedWorkerSpool(tmp_path / "spool")
    spool.enqueue(
        SignedNucleiWorkerJob.create(
            job_id="assessment-pilot",
            invocation=invocation,
            key=key,
            created_at=NOW,
        )
    )
    policy = NucleiPilotPolicy(
        enabled=True,
        worker_id="private-lab-worker",
        nuclei_executable=_fake_nuclei(tmp_path),
        template_root=(_repository_root() / "config/security_tools/pilot_templates").resolve(),
        maximum_rate_limit=1,
        maximum_concurrency=1,
        maximum_observations=10,
        private_targets_only=True,
    )
    agent_store = _task_store(tmp_path, invocation)
    evidence_store = EvidenceStore(tmp_path / "evidence")
    activity = AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity"))
    service = NucleiPilotWorkerService(
        spool=spool,
        signing_key=key,
        policy=policy,
        compatibility_manifest=_compatibility(),
        template_manifest=_template_manifest(),
        execution_store=NucleiExecutionStore(tmp_path / "execution-state"),
        evidence_store=evidence_store,
        verification_store=OracleStore(tmp_path / "verification"),
        agent_store=agent_store,
        activity_service=activity,
        clock=lambda: NOW + timedelta(seconds=2),
    )

    receipt = service.run_once()

    assert receipt is not None
    assert receipt.state == ScannerJobState.COMPLETED.value
    records = evidence_store.list()
    assert len(records) == 1
    assert records[0].title == "Passive Security Header Review"
    assert records[0].metadata["scanner"] == "nuclei"
    assert records[0].metadata["verification_status"] in {"verified", "abstain"}
    assert records[0].finding_status.value in {"candidate", "validated"}
    task = agent_store.get_task("assessment-pilot")
    assert task.status is TaskStatus.COMPLETED
    feed = activity.feed("assessment-pilot")
    assert [event.event_type for event in feed.events] == [
        "tool_execution_started",
        "tool_execution_completed",
    ]
    assert all("secret" not in event.summary.lower() for event in feed.events)


def test_mobile_static_worker_uses_read_only_copy_and_fixed_tool(tmp_path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libsample.so", b"native")
    ingestor = MobileArtifactIngestor(tmp_path / "mobile-artifacts")
    record = ingestor.ingest_file(apk.resolve())
    tool = tmp_path / "aapt2"
    tool.write_text("#!/bin/sh\necho package: name=com.example.safe\n", encoding="utf-8")
    tool.chmod(0o700)
    policy = MobileStaticWorkerPolicy(
        enabled=True,
        worker_id="mobile-static-worker",
        workspace_root=(tmp_path / "mobile-work").resolve(),
        aapt2_executable=tool.resolve(),
        timeout_seconds=10,
        maximum_output_bytes=10_000,
    )

    result = MobileStaticWorker(policy).analyze(record)

    assert result.state == "completed"
    assert result.captures[0].tool == "aapt2"
    assert result.candidate_observations[0]["title"] == "APK contains native libraries"
    copied = policy.workspace_root / record.artifact_id / f"{record.artifact_id}.apk"
    assert copied.stat().st_mode & 0o222 == 0
    assert os.path.exists(policy.workspace_root / record.artifact_id / "static-analysis.json")


def test_worker_spool_cancels_pending_and_recovers_claimed_jobs(tmp_path):
    invocation = _invocation(tmp_path)
    key = b"r" * 32
    spool = SignedWorkerSpool(tmp_path / "recovery-spool")
    pending = SignedNucleiWorkerJob.create(
        job_id="assessment-pending",
        invocation=invocation,
        key=key,
        created_at=NOW,
    )
    spool.enqueue(pending)
    assert (
        spool.request_cancellation(
            "assessment-pending",
            reason="Operator requested stop.",
            now=NOW + timedelta(seconds=1),
        )
        == "pending_cancelled"
    )
    assert not (spool.pending / "assessment-pending.json").exists()
    assert (spool.failed / "assessment-pending.receipt.json").is_file()

    claimed_job = SignedNucleiWorkerJob.create(
        job_id="assessment-recovery",
        invocation=invocation,
        key=key,
        created_at=NOW,
    )
    spool.enqueue(claimed_job)
    claimed = spool.claim_next()
    assert claimed is not None
    spool.request_cancellation(
        "assessment-recovery",
        reason="Stop claimed job.",
        now=NOW + timedelta(seconds=2),
    )
    assert spool.cancellation_requested("assessment-recovery") is True
    recovered = spool.recover_processing(now=NOW + timedelta(seconds=3))
    assert len(recovered) == 1
    assert recovered[0].parent == spool.failed
    assert not spool.cancellation_requested("assessment-recovery")
