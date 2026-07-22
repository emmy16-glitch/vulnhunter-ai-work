from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC

from vulnhunter.security_tools.nuclei_pilot_service import NucleiPilotWorkerService
from vulnhunter.security_tools.remote_nuclei_worker import (
    RemoteNucleiWorkerError,
    RestrictedSshNucleiRunner,
)
from vulnhunter.security_tools.scanner_protocol import ScannerAdapterResult, ScannerJobState
from vulnhunter.security_tools.verification_pipeline import EvidenceVerificationPipeline
from vulnhunter.security_tools.worker_spool import WorkerJobReceipt


@dataclass(frozen=True)
class _RemoteHarnessPolicy:
    enabled: bool


class RemoteNucleiPilotWorkerService(NucleiPilotWorkerService):
    """Process the existing signed spool while executing through restricted SSH."""

    def __init__(self, *, remote_runner: RestrictedSshNucleiRunner, **kwargs) -> None:
        self.remote_policy = _RemoteHarnessPolicy(enabled=remote_runner.policy.enabled)
        super().__init__(policy=self.remote_policy, **kwargs)
        self.remote_runner = remote_runner

    def _process(self, job) -> WorkerJobReceipt:
        invocation = job.invocation.model_copy(update={"now": self.clock().astimezone(UTC)})
        target_pins = {
            target.hostname: target.resolved_addresses
            for target in invocation.request.exact_targets
        }

        def resolver(hostname: str) -> tuple[str, ...]:
            try:
                return target_pins[hostname]
            except KeyError as exc:
                raise RemoteNucleiWorkerError(
                    "worker resolver received an unapproved host"
                ) from exc

        from vulnhunter.security_tools.nuclei_worker_pilot import NucleiPilotExecutionHarness

        harness = NucleiPilotExecutionHarness(
            policy=self.remote_policy,
            store=self.execution_store,
            runner=self.remote_runner,
            resolver=resolver,
            approved_output_root=self.evidence_store.root,
            compatibility_manifest=self.compatibility_manifest,
            external_cancellation=lambda: self.spool.cancellation_requested(job.job_id),
        )
        self._activity(
            job.job_id,
            "tool_execution_started",
            "Starting restricted remote passive scan.",
            "executing",
        )
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
            outcomes = EvidenceVerificationPipeline(
                evidence_store=self.evidence_store,
                verification_store=self.verification_store,
            ).process(
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
            job.job_id,
            record.state,
            len(outcomes),
            record.request.execution_id,
        )
        completed = record.state is ScannerJobState.COMPLETED
        self._activity(
            job.job_id,
            "tool_execution_completed" if completed else "tool_execution_failed",
            (
                f"Remote passive scan completed with {len(record.observations)} candidate "
                "observation(s)."
                if completed
                else f"Remote passive scan ended in state {record.state.value}."
            ),
            "completed" if completed else "failed",
            metadata={
                "execution_id": record.request.execution_id,
                "candidate_observations": len(record.observations),
                "unified_findings": len(outcomes),
                "worker_transport": "restricted_ssh",
            },
        )
        return WorkerJobReceipt.from_record(
            job_id=job.job_id,
            record=record,
            completed_at=self.clock(),
        )
