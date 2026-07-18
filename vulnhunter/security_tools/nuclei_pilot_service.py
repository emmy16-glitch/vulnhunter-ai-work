"""Manager enqueue and isolated-worker processing for the passive Nuclei pilot."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from vulnhunter.agent.models import AgentTask, TaskStatus
from vulnhunter.agent.store import AgentStore, AgentStoreError
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.approvals import ApprovalRequest, ApprovalStatus
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.evidence.store import EvidenceStore
from vulnhunter.oracle.store import OracleStore
from vulnhunter.security_tools.nuclei_activation import (
    EngagementAuthorization,
    NucleiCommandPlan,
    NucleiPlanApproval,
    NucleiTemplateManifest,
)
from vulnhunter.security_tools.nuclei_execution import (
    NucleiExecutionInvocation,
    NucleiExecutionRequest,
    NucleiExecutionStore,
    NucleiRuntimeReadiness,
)
from vulnhunter.security_tools.nuclei_worker_pilot import (
    NucleiPilotExecutionHarness,
    NucleiPilotPolicy,
    PassiveNucleiProcessRunner,
)
from vulnhunter.security_tools.scanner_protocol import (
    ScannerAdapterResult,
    ScannerCompatibilityManifest,
    ScannerExecutionLimits,
    ScannerJobState,
)
from vulnhunter.security_tools.verification_pipeline import EvidenceVerificationPipeline
from vulnhunter.security_tools.worker_spool import (
    SignedNucleiWorkerJob,
    SignedWorkerSpool,
    WorkerJobReceipt,
    WorkerSpoolError,
)


class NucleiPilotServiceError(RuntimeError):
    """Raised when the manager or worker cannot preserve the pilot boundary."""


def _load_nuclei_authorization(
    store: AuthorizationStore,
    authorization_id: str,
) -> EngagementAuthorization:
    record = store.get(authorization_id)
    for event in store.list_events(authorization_id):
        if event.event_type != "nuclei_activation_bound":
            continue
        if event.detail.get("source_record_sha256") != record.record_sha256:
            raise NucleiPilotServiceError("Nuclei binding is stale")
        try:
            engagement = EngagementAuthorization.model_validate(
                event.detail.get("engagement_record")
            )
        except (TypeError, ValueError) as exc:
            raise NucleiPilotServiceError("Nuclei binding is invalid") from exc
        if engagement.authorization_id != record.authorization_id:
            raise NucleiPilotServiceError("Nuclei binding references another authorization")
        return engagement
    raise NucleiPilotServiceError("No reviewed Nuclei activation binding exists")


def build_approved_pilot_job(
    *,
    task: AgentTask,
    approval_request: ApprovalRequest,
    authorization_store: AuthorizationStore,
    compatibility_manifest: ScannerCompatibilityManifest,
    signing_key: bytes,
    actor_id: str,
    now: datetime,
) -> SignedNucleiWorkerJob:
    """Build one signed job from an approved passive plan already stored by the manager."""

    if approval_request.status is not ApprovalStatus.APPROVED:
        raise NucleiPilotServiceError("the worker job requires an approved request")
    if approval_request.run_id != task.task_id:
        raise NucleiPilotServiceError("approval and assessment run do not match")
    workflow = task.memory.get("assessment_workflow")
    if not isinstance(workflow, dict):
        raise NucleiPilotServiceError("assessment workflow state is unavailable")
    plan_payload = workflow.get("command_plan")
    if not isinstance(plan_payload, dict):
        raise NucleiPilotServiceError("approved command plan is unavailable")
    try:
        plan = NucleiCommandPlan.model_validate(plan_payload)
    except ValueError as exc:
        raise NucleiPilotServiceError("approved command plan is invalid") from exc
    if plan.exact_profile != "passive":
        raise NucleiPilotServiceError("the worker pilot accepts the passive profile only")
    if plan.rate_limit != 1 or plan.concurrency != 1:
        raise NucleiPilotServiceError("the worker pilot requires rate and concurrency of one")
    if approval_request.action_manifest_sha256 != plan.plan_digest:
        raise NucleiPilotServiceError("approval is not bound to the current plan digest")
    if not approval_request.decided_at or not approval_request.decided_by:
        raise NucleiPilotServiceError("approval decision metadata is incomplete")

    authorization = _load_nuclei_authorization(
        authorization_store,
        plan.authorization_id,
    )
    approval = NucleiPlanApproval(
        approval_id=approval_request.request_id,
        authorization_id=plan.authorization_id,
        command_plan_digest=plan.plan_digest,
        approved_by=approval_request.decided_by,
        approved_at=approval_request.decided_at,
        expires_at=min(approval_request.expires_at, plan.expires_at),
    )
    pin = compatibility_manifest.get("nuclei").version_pin
    if pin.engine_version is None or pin.feed is None or pin.feed.release is None:
        raise NucleiPilotServiceError("Nuclei compatibility pins are incomplete")
    readiness = NucleiRuntimeReadiness(
        engine_version=pin.engine_version,
        template_release=pin.feed.release,
        template_manifest_hashes=plan.template_manifest_hashes,
        compatibility_manifest_sha256=compatibility_manifest.fingerprint(),
        checked_at=now,
    )
    limits = ScannerExecutionLimits(
        timeout_seconds=300,
        maximum_stdout_bytes=200_000,
        maximum_stderr_bytes=100_000,
        concurrency=1,
        rate_limit=1,
        termination_grace_seconds=2,
    )
    request = NucleiExecutionRequest.from_plan(
        execution_id=f"execution-{uuid4().hex[:20]}",
        plan=plan,
        approval=approval,
        limits=limits,
        cancellation_id=f"cancel-{uuid4().hex[:20]}",
        correlation_id=task.task_id,
        compatibility_manifest_sha256=compatibility_manifest.fingerprint(),
    )
    invocation = NucleiExecutionInvocation(
        request=request,
        plan=plan,
        approval=approval,
        authorization=authorization,
        readiness=readiness,
        actor_id=actor_id,
        now=now.astimezone(UTC),
    )
    return SignedNucleiWorkerJob.create(
        job_id=task.task_id,
        invocation=invocation,
        key=signing_key,
        created_at=now,
    )


class NucleiPilotWorkerService:
    """Claim one authenticated job, execute it, verify evidence, and update the run."""

    def __init__(
        self,
        *,
        spool: SignedWorkerSpool,
        signing_key: bytes,
        policy: NucleiPilotPolicy,
        compatibility_manifest: ScannerCompatibilityManifest,
        template_manifest: NucleiTemplateManifest,
        execution_store: NucleiExecutionStore,
        evidence_store: EvidenceStore,
        verification_store: OracleStore,
        agent_store: AgentStore,
        activity_service: AgentActivityService,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self.spool = spool
        self.signing_key = signing_key
        self.policy = policy
        self.compatibility_manifest = compatibility_manifest
        self.template_manifest = template_manifest
        self.execution_store = execution_store
        self.evidence_store = evidence_store
        self.verification_store = verification_store
        self.agent_store = agent_store
        self.activity_service = activity_service
        self.clock = clock

    def run_once(self) -> WorkerJobReceipt | None:
        claimed = self.spool.claim_next()
        if claimed is None:
            return None
        now = self.clock().astimezone(UTC)
        try:
            job = self.spool.load_claimed(claimed, key=self.signing_key, now=now)
            receipt = self._process(job)
        except Exception as exc:
            self.spool.reject(
                claimed,
                reason=f"Worker job rejected safely: {type(exc).__name__}",
                now=now,
            )
            if isinstance(exc, (WorkerSpoolError, NucleiPilotServiceError)):
                raise
            raise NucleiPilotServiceError("worker job failed closed") from exc
        self.spool.finish(
            claimed,
            receipt=receipt,
            success=receipt.state == ScannerJobState.COMPLETED.value,
        )
        return receipt

    def _process(self, job: SignedNucleiWorkerJob) -> WorkerJobReceipt:
        invocation = job.invocation.model_copy(update={"now": self.clock().astimezone(UTC)})
        target_pins = {
            target.hostname: target.resolved_addresses
            for target in invocation.request.exact_targets
        }

        def resolver(hostname: str) -> tuple[str, ...]:
            try:
                return target_pins[hostname]
            except KeyError as exc:
                raise NucleiPilotServiceError(
                    "worker resolver received an unapproved host"
                ) from exc

        runner = PassiveNucleiProcessRunner(
            policy=self.policy,
            template_manifest=self.template_manifest,
        )
        harness = NucleiPilotExecutionHarness(
            policy=self.policy,
            store=self.execution_store,
            runner=runner,
            resolver=resolver,
            approved_output_root=self.evidence_store.root,
            compatibility_manifest=self.compatibility_manifest,
        )
        self._activity(job.job_id, "scanner_starting", "Starting isolated passive scan.", "running")
        record = harness.execute_pilot(invocation)
        adapter_result = ScannerAdapterResult(
            execution_id=record.request.execution_id,
            state=record.state,
            observations=record.observations,
            evidence=record.evidence,
            reason=(
                record.stderr.text if record.stderr and record.stderr.text else record.state.value
            ),
        )
        outcomes = ()
        if record.state is ScannerJobState.COMPLETED:
            pipeline = EvidenceVerificationPipeline(
                evidence_store=self.evidence_store,
                verification_store=self.verification_store,
            )
            outcomes = pipeline.process(
                adapter_result,
                campaign_id=invocation.approval.approval_id,
                run_id=job.job_id,
                authorization_reference=invocation.authorization.authorization_id,
                approval_reference=invocation.approval.approval_id,
                action_manifest_sha256=invocation.plan.plan_digest,
                target_reference=invocation.plan.exact_targets[0].url,
                adapter_version=(
                    self.compatibility_manifest.get("nuclei").version_pin.adapter_version
                ),
                tool_version=invocation.readiness.engine_version,
                recorded_by=invocation.actor_id,
            )
        self._project_run_state(
            job.job_id, record.state, len(outcomes), record.request.execution_id
        )
        self._activity(
            job.job_id,
            "scanner_completed" if record.state is ScannerJobState.COMPLETED else "scanner_failed",
            (
                f"Passive scan completed with {len(record.observations)} candidate observation(s)."
                if record.state is ScannerJobState.COMPLETED
                else f"Passive scan ended in state {record.state.value}."
            ),
            "completed" if record.state is ScannerJobState.COMPLETED else "failed",
            metadata={
                "execution_id": record.request.execution_id,
                "candidate_observations": len(record.observations),
                "unified_findings": len(outcomes),
            },
        )
        return WorkerJobReceipt.from_record(
            job_id=job.job_id,
            record=record,
            completed_at=self.clock(),
        )

    def _project_run_state(
        self,
        run_id: str,
        state: ScannerJobState,
        finding_count: int,
        execution_id: str,
    ) -> None:
        try:
            task = self.agent_store.get_task(run_id)
        except AgentStoreError:
            return
        workflow = task.memory.get("assessment_workflow")
        if not isinstance(workflow, dict):
            return
        if state is ScannerJobState.COMPLETED:
            task_status = TaskStatus.COMPLETED
            workflow_state = "completed"
            blocking_reason = None
        elif state is ScannerJobState.CANCELLED:
            task_status = TaskStatus.CANCELLED
            workflow_state = "cancelled"
            blocking_reason = "The isolated worker job was cancelled."
        elif state is ScannerJobState.TIMED_OUT:
            task_status = TaskStatus.TIMED_OUT
            workflow_state = "timed_out"
            blocking_reason = "The isolated worker job timed out."
        else:
            task_status = TaskStatus.FAILED
            workflow_state = "failed"
            blocking_reason = "The isolated worker job failed closed."
        updated = task.evolved(
            status=task_status,
            paused_reason=blocking_reason,
            memory={
                **task.memory,
                "assessment_workflow": {
                    **workflow,
                    "workflow_state": workflow_state,
                    "execution_state": state.value,
                    "execution_id": execution_id,
                    "finding_count": finding_count,
                    "execution_enabled": False,
                    "blocking_reason": blocking_reason,
                },
            },
        )
        self.agent_store.save_task(updated, expected_revision=task.revision)
        self.agent_store.append_event(
            run_id,
            "scanner.result",
            {
                "execution_id": execution_id,
                "state": state.value,
                "finding_count": finding_count,
            },
        )

    def _activity(
        self,
        run_id: str,
        event_type: str,
        summary: str,
        run_state: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> None:
        self.activity_service.record_transition(
            run_id=run_id,
            timestamp=self.clock(),
            event_type=event_type,
            summary=summary,
            run_state=run_state,
            source="isolated-nuclei-worker",
            metadata=metadata or {},
        )


__all__ = [
    "NucleiPilotServiceError",
    "NucleiPilotWorkerService",
    "build_approved_pilot_job",
]
