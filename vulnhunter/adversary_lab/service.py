"""Bounded orchestration for controlled adversary-emulation trials."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.adversary_lab.models import LabPlan, LabRecord, LabState, TrialOutcome
from vulnhunter.adversary_lab.registry import get_scenario
from vulnhunter.adversary_lab.runner import LabRunnerError, SyntheticScenarioRunner
from vulnhunter.adversary_lab.store import AdversaryLabStore
from vulnhunter.agent_activity.service import AgentActivityService


class AdversaryLabServiceError(RuntimeError):
    """Raised when a lab transition violates its governed lifecycle."""


class AdversaryLabService:
    """Create, approve, queue, execute, cancel, and audit safe synthetic lab runs."""

    def __init__(
        self,
        *,
        store: AdversaryLabStore,
        activity_service: AgentActivityService,
        runner: SyntheticScenarioRunner,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.store = store
        self.activity_service = activity_service
        self.runner = runner
        self.clock = clock

    def _now(self) -> datetime:
        return self.clock().astimezone(UTC)

    def _save(self, record: LabRecord, **updates: object) -> LabRecord:
        current = self._now()
        updated = record.model_copy(
            update={
                **updates,
                "updated_at": current,
                "revision": record.revision + 1,
            }
        )
        return self.store.save(updated, expected_revision=record.revision)

    def _event(
        self,
        record: LabRecord,
        *,
        event_type: str,
        summary: str,
        run_state: str,
        source: str,
        **fields: object,
    ) -> None:
        self.activity_service.record_transition(
            run_id=record.plan.lab_id,
            timestamp=self._now(),
            event_type=event_type,
            summary=summary,
            run_state=run_state,
            source=source,
            role_id="system-administrator",
            skill_id="controlled-impact-simulation",
            authorization_reference=record.plan.authorization_id,
            scope_reference=record.plan.finding_reference,
            risk_level="high",
            **fields,
        )

    def create_plan(
        self,
        *,
        assessment_id: str,
        finding_reference: str,
        authorization_id: str,
        target_reference: str,
        scenario_id: str,
        maximum_trials: int,
        requested_by: str,
    ) -> LabRecord:
        scenario = get_scenario(scenario_id)
        now = self._now()
        lab_id = f"lab_{uuid4().hex[:24]}"
        plan = LabPlan.create(
            lab_id=lab_id,
            assessment_id=assessment_id,
            finding_reference=finding_reference,
            authorization_id=authorization_id,
            target_reference=target_reference,
            scenario=scenario,
            requested_by=requested_by,
            requested_at=now,
            maximum_trials=maximum_trials,
        )
        record = self.store.create(
            LabRecord(
                plan=plan,
                created_at=now,
                updated_at=now,
                active_summary="Waiting for independent approval of the exact lab plan.",
            )
        )
        self._event(
            record,
            event_type="run_created",
            summary="A controlled impact-simulation run was created.",
            run_state="created",
            source="runtime",
        )
        self._event(
            record,
            event_type="objective_received",
            summary="The assessment finding was bound to a synthetic lab objective.",
            run_state="created",
            source="runtime",
            metadata={"finding_reference": finding_reference},
        )
        self._event(
            record,
            event_type="planning_started",
            summary="Preparing the reviewed synthetic scenario and bounded retry policy.",
            run_state="planning",
            source="planner",
        )
        self._event(
            record,
            event_type="plan_proposed",
            summary=(
                f"The plan permits {plan.minimum_trials} to {plan.maximum_trials} clean-snapshot "
                "trials with no public network route."
            ),
            run_state="planning",
            source="planner",
            audit_reference=plan.plan_digest,
            metadata={
                "scenario_id": scenario.scenario_id,
                "maximum_trials": plan.maximum_trials,
                "minimum_trials": plan.minimum_trials,
                "required_confirmations": plan.required_confirmations,
            },
        )
        self._event(
            record,
            event_type="approval_requested",
            summary="Independent approval is required for the exact plan digest.",
            run_state="awaiting_approval",
            source="approval",
            approval_requirement="required",
            approval_state="pending",
            audit_reference=plan.plan_digest,
        )
        return record

    def approve(self, lab_id: str, *, approved_by: str) -> LabRecord:
        record = self.store.get(lab_id)
        if record.state is not LabState.AWAITING_APPROVAL:
            raise AdversaryLabServiceError("this lab plan is not awaiting approval")
        if approved_by == record.plan.requested_by:
            raise AdversaryLabServiceError("the requester cannot approve the same lab plan")
        if record.plan.plan_digest != record.plan.fingerprint():
            raise AdversaryLabServiceError("the lab plan digest changed before approval")
        approved = self._save(
            record,
            state=LabState.APPROVED,
            approved_by=approved_by,
            approved_at=self._now(),
            approved_plan_digest=record.plan.plan_digest,
            active_summary="Approved plan is ready for a fresh step-up execution request.",
        )
        self._event(
            approved,
            event_type="approval_granted",
            summary="An independent approver accepted the exact synthetic lab plan.",
            run_state="awaiting_approval",
            source="approval",
            approval_requirement="required",
            approval_state="granted",
            audit_reference=approved.plan.plan_digest,
            metadata={"approved_by": approved_by},
        )
        return approved

    def queue(self, lab_id: str, *, queued_by: str) -> LabRecord:
        record = self.store.get(lab_id)
        if record.state is not LabState.APPROVED:
            raise AdversaryLabServiceError("only an approved lab plan can be queued")
        if record.approved_plan_digest != record.plan.plan_digest:
            raise AdversaryLabServiceError("approval is not bound to the current plan digest")
        queued = self._save(
            record,
            state=LabState.QUEUED,
            queued_by=queued_by,
            active_summary="Waiting for the isolated synthetic lab worker.",
        )
        self._event(
            queued,
            event_type="tool_progress",
            summary="The approved plan was queued for the isolated synthetic lab worker.",
            run_state="executing",
            source="system",
            approval_requirement="required",
            approval_state="granted",
            execution_state="queued",
            audit_reference=queued.plan.plan_digest,
        )
        return queued

    def request_cancel(self, lab_id: str, *, actor_id: str, reason: str) -> LabRecord:
        record = self.store.request_cancellation(lab_id, reason=reason, now=self._now())
        self._event(
            record,
            event_type="stop_requested",
            summary="A human operator requested that the lab run stop.",
            run_state="stopping",
            source="operator",
            execution_state="cancelled" if record.state is LabState.CANCELLED else "running",
            metadata={"actor_id": actor_id, "reason": reason},
        )
        if record.state is LabState.CANCELLED:
            self._event(
                record,
                event_type="run_stopped",
                summary="The lab run stopped before a worker trial began.",
                run_state="stopped",
                source="system",
                execution_state="cancelled",
            )
        return record

    def run_next(self) -> LabRecord | None:
        claimed = self.store.claim_next(now=self._now())
        if claimed is None:
            return None
        return self._execute(claimed)

    def _execute(self, record: LabRecord) -> LabRecord:
        plan = record.plan
        try:
            if plan.plan_digest != plan.fingerprint():
                raise AdversaryLabServiceError("the worker rejected a changed plan digest")
            if record.approved_plan_digest != plan.plan_digest:
                raise AdversaryLabServiceError("the worker rejected an unbound approval")
            if record.approved_by is None or record.approved_by == plan.requested_by:
                raise AdversaryLabServiceError("independent approval is missing")

            self._event(
                record,
                event_type="authorization_check_started",
                summary="Checking the assessment authorization bound to the lab plan.",
                run_state="checking_authorization",
                source="policy",
            )
            self._event(
                record,
                event_type="authorization_check_passed",
                summary="The lab plan remains bound to its recorded assessment authorization.",
                run_state="checking_authorization",
                source="policy",
                policy_outcome="allowed",
            )
            self._event(
                record,
                event_type="scope_check_started",
                summary="Checking synthetic-data and no-egress scope controls.",
                run_state="checking_scope",
                source="policy",
            )
            if plan.public_targets_allowed or plan.arbitrary_commands_allowed:
                raise AdversaryLabServiceError("the signed plan requests a prohibited capability")
            self._event(
                record,
                event_type="scope_check_passed",
                summary="The plan is restricted to generated data and an isolated no-egress range.",
                run_state="checking_scope",
                source="policy",
                policy_outcome="allowed",
            )
            self._event(
                record,
                event_type="policy_check_started",
                summary="Validating the reviewed scenario and ten-trial ceiling.",
                run_state="checking_policy",
                source="policy",
            )
            if plan.maximum_trials > 10:
                raise AdversaryLabServiceError("the plan exceeds the hard ten-trial ceiling")
            self._event(
                record,
                event_type="policy_allowed",
                summary="The reviewed synthetic scenario passed the worker policy gate.",
                run_state="checking_policy",
                source="policy",
                policy_outcome="allowed",
            )

            self.runner.prepare(plan)
            record = self._save(
                self.store.get(plan.lab_id),
                state=LabState.RUNNING,
                active_summary="Restoring the baseline snapshot for the first trial.",
            )
            self._event(
                record,
                event_type="tool_execution_started",
                summary="The isolated synthetic lab worker started the approved scenario.",
                run_state="executing",
                source="tool",
                tool_id="adversary-lab-synthetic-runner",
                approval_requirement="required",
                approval_state="granted",
                execution_state="running",
            )

            deadline = (record.started_at or self._now()) + timedelta(
                seconds=plan.total_timeout_seconds
            )
            for trial_number, variation in enumerate(plan.variations, start=1):
                current = self.store.get(plan.lab_id)
                if current.cancellation_requested:
                    return self._cancel_during_execution(current)
                if self._now() >= deadline:
                    raise AdversaryLabServiceError("the total lab runtime budget expired")

                current = self._save(
                    current,
                    state=LabState.RUNNING,
                    current_trial=trial_number,
                    active_summary=(
                        f"Trial {trial_number} of {plan.maximum_trials}: restoring the clean snapshot."
                    ),
                )
                self._event(
                    current,
                    event_type="tool_progress",
                    summary=(
                        f"Trial {trial_number} of {plan.maximum_trials}: restoring the clean snapshot."
                    ),
                    run_state="executing",
                    source="tool",
                    tool_id="snapshot-controller",
                    execution_state="running",
                    metadata={"trial": trial_number, "variation": variation},
                )
                trial_started = self._now()
                trial = self.runner.execute_trial(
                    plan,
                    trial_number=trial_number,
                    variation=variation,
                    started_at=trial_started,
                )
                elapsed = (trial.completed_at - trial.started_at).total_seconds()
                if elapsed > plan.per_trial_timeout_seconds:
                    raise AdversaryLabServiceError("a trial exceeded its signed timeout")

                current = self.store.get(plan.lab_id)
                confirmed = current.confirmed_trials + (
                    1 if trial.outcome is TrialOutcome.CONFIRMED else 0
                )
                inconclusive = current.inconclusive_trials + (
                    1 if trial.outcome is TrialOutcome.INCONCLUSIVE else 0
                )
                failed = current.failed_trials + (1 if trial.outcome is TrialOutcome.FAILED else 0)
                current = self._save(
                    current,
                    trials=(*current.trials, trial),
                    confirmed_trials=confirmed,
                    inconclusive_trials=inconclusive,
                    failed_trials=failed,
                    active_summary=(
                        f"Trial {trial_number} completed; validating evidence consistency."
                    ),
                )
                self._event(
                    current,
                    event_type="tool_progress",
                    summary=(f"Trial {trial_number} completed with outcome {trial.outcome.value}."),
                    run_state="executing",
                    source="tool",
                    tool_id="adversary-lab-synthetic-runner",
                    execution_state="running",
                    audit_reference=trial.evidence_sha256,
                    metadata={
                        "trial": trial_number,
                        "outcome": trial.outcome.value,
                        "snapshot_restored": trial.snapshot_restored,
                    },
                )

                enough_trials = trial_number >= plan.minimum_trials
                enough_confirmations = confirmed >= plan.required_confirmations
                if enough_trials and enough_confirmations:
                    break
                if trial_number < plan.maximum_trials:
                    self._event(
                        current,
                        event_type="retry_scheduled",
                        summary=(
                            f"A clean-snapshot retry was scheduled for trial {trial_number + 1}."
                        ),
                        run_state="executing",
                        source="evaluator",
                        execution_state="queued",
                        metadata={"next_trial": trial_number + 1},
                    )

            record = self._save(
                self.store.get(plan.lab_id),
                state=LabState.EVALUATING,
                active_summary="Consolidating trial evidence into one validation result.",
            )
            self._event(
                record,
                event_type="evaluation_started",
                summary="Consolidating the bounded trial evidence.",
                run_state="evaluating",
                source="evaluator",
            )
            result = (
                "confirmed"
                if record.confirmed_trials >= plan.required_confirmations
                else "inconclusive"
            )
            self._event(
                record,
                event_type="evaluation_completed",
                summary=(f"Impact simulation result: {result}; human review remains required."),
                run_state="evaluating",
                source="evaluator",
                metadata={
                    "result": result,
                    "confirmed_trials": record.confirmed_trials,
                    "total_trials": len(record.trials),
                },
            )

            record = self._save(
                self.store.get(plan.lab_id),
                state=LabState.CLEANING,
                active_summary="Destroying the disposable workspace and verifying cleanup.",
            )
            cleanup_verified = self.runner.cleanup(plan)
            if not cleanup_verified:
                raise AdversaryLabServiceError(
                    "the disposable workspace cleanup could not be verified"
                )
            record = self._save(
                self.store.get(plan.lab_id),
                state=LabState.COMPLETED,
                cleanup_verified=True,
                result=result,
                active_summary="Lab trials completed; human review is pending.",
                completed_at=self._now(),
            )
            self._event(
                record,
                event_type="tool_execution_completed",
                summary="The synthetic lab worker completed and the disposable workspace was removed.",
                run_state="completed",
                source="tool",
                tool_id="adversary-lab-synthetic-runner",
                execution_state="succeeded",
            )
            self._event(
                record,
                event_type="run_completed",
                summary="The controlled impact simulation completed without publishing a finding.",
                run_state="completed",
                source="runtime",
                execution_state="succeeded",
                metadata={"result": result, "human_review_state": "pending"},
            )
            return record
        except (AdversaryLabServiceError, LabRunnerError, OSError, ValueError) as exc:
            return self._fail_closed(record.plan.lab_id, exc)

    def _cancel_during_execution(self, record: LabRecord) -> LabRecord:
        cleanup_verified = self.runner.cleanup(record.plan)
        cancelled = self._save(
            record,
            state=LabState.CANCELLED,
            cleanup_verified=cleanup_verified,
            active_summary="The lab run stopped and cleanup was checked.",
            completed_at=self._now(),
        )
        self._event(
            cancelled,
            event_type="run_stopped",
            summary="The lab run stopped at a safe checkpoint and the workspace was removed.",
            run_state="stopped",
            source="system",
            execution_state="cancelled",
            metadata={"cleanup_verified": cleanup_verified},
        )
        return cancelled

    def _fail_closed(self, lab_id: str, exc: Exception) -> LabRecord:
        record = self.store.get(lab_id)
        cleanup_verified = False
        try:
            cleanup_verified = self.runner.cleanup(record.plan)
        except (LabRunnerError, OSError):
            cleanup_verified = False
        failed = self._save(
            record,
            state=LabState.FAILED,
            cleanup_verified=cleanup_verified,
            result="failed_closed",
            active_summary="The lab run failed closed; review the recorded error state.",
            completed_at=self._now(),
        )
        error_name = type(exc).__name__
        self._event(
            failed,
            event_type="tool_execution_failed",
            summary=f"The synthetic lab worker failed closed: {error_name}.",
            run_state="failed",
            source="tool",
            tool_id="adversary-lab-synthetic-runner",
            execution_state="failed",
            error_code="lab_worker_failed",
            error_message=error_name,
            metadata={"cleanup_verified": cleanup_verified},
        )
        self._event(
            failed,
            event_type="run_failed",
            summary="The controlled impact simulation ended in a failed-closed state.",
            run_state="failed",
            source="runtime",
            execution_state="failed",
        )
        return failed
