"""Bounded execution controller that owns the complete agent loop."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import (
    AgentApprovalBinding,
    AgentProposal,
    AgentTask,
    EvaluationStatus,
    ExecutionReport,
    PermissionManifest,
    PolicyStatus,
    ProposalKind,
    RuntimeConfig,
    TaskStatus,
    sha256_json,
    utc_now,
)
from vulnhunter.agent.planner import Planner, PlannerError
from vulnhunter.agent.policy import AgentPolicyEngine
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent.tools import ToolRegistry, ToolRegistryError
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.approvals.service import ApprovalService


@dataclass(frozen=True)
class AgentRuntime:
    """Dependencies for one controller instance."""

    config: RuntimeConfig
    store: AgentStore
    planner: Planner
    tools: ToolRegistry
    evaluator: ResultEvaluator
    activity_service: AgentActivityService | None = None
    approval_service: ApprovalService | None = None
    clock: Callable[[], datetime] = utc_now


class AgentController:
    """Execute, pause, resume, and audit bounded agent tasks."""

    def __init__(self, runtime: AgentRuntime) -> None:
        self.runtime = runtime
        self.policy = AgentPolicyEngine(runtime.config)

    def create_task(
        self,
        *,
        task_id: str,
        objective: str,
        permission_manifest: PermissionManifest,
        approval_binding: AgentApprovalBinding | None = None,
    ) -> AgentTask:
        if approval_binding is not None:
            self._validate_approval_binding(permission_manifest, approval_binding, task_id)
        created_at = self._now()
        task = AgentTask(
            task_id=task_id,
            objective=objective,
            permission_manifest=permission_manifest,
            approval_binding=approval_binding,
            created_at=created_at,
            updated_at=created_at,
            deadline_at=created_at + timedelta(seconds=permission_manifest.maximum_runtime_seconds),
        )
        self.runtime.store.create_task(task)
        created = self.runtime.store.append_event(
            task.task_id,
            "task.created",
            {
                "objective": task.objective,
                "permission_manifest_sha256": permission_manifest.fingerprint(),
            },
        )
        self._record_activity(
            run_id=task.task_id,
            event_type="run_created",
            summary="The bounded run was created.",
            run_state="created",
            source="runtime",
            timestamp=task.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            audit_reference=created.event_sha256,
        )
        self._record_activity(
            run_id=task.task_id,
            event_type="objective_received",
            summary="A bounded objective was recorded for the run.",
            run_state="created",
            source="runtime",
            timestamp=task.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            audit_reference=created.event_sha256,
            metadata={
                "objective_sha256": self._objective_reference(task.objective),
                "objective_summary": "Bounded local objective recorded for governed execution.",
            },
        )
        self._record_activity(
            run_id=task.task_id,
            event_type="role_selected",
            summary="The run selected a specialist role from the permission manifest.",
            run_state="created",
            source="runtime",
            timestamp=task.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            audit_reference=created.event_sha256,
        )
        if task.permission_manifest.skill_id:
            self._record_activity(
                run_id=task.task_id,
                event_type="skill_selected",
                summary="The run selected a specialist skill from the permission manifest.",
                run_state="created",
                source="runtime",
                timestamp=task.created_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                audit_reference=created.event_sha256,
            )
        return task

    def run(self, task_id: str, *, max_iterations: int | None = None) -> AgentTask:
        task = self.runtime.store.get_task(task_id)
        if task.terminal:
            return task
        if self._deadline_expired(task):
            return self._time_out(task, phase="before_planning")
        if task.status == TaskStatus.PAUSED_OPERATOR:
            return task
        if task.status == TaskStatus.PAUSED_APPROVAL and not task.memory.get(
            "approved_pending_call"
        ):
            return task

        task = self._save(task, status=TaskStatus.RUNNING, paused_reason=None)
        self._record_activity(
            run_id=task.task_id,
            event_type="planning_started",
            summary="The bounded runtime started planning the next safe action.",
            run_state="planning",
            source="planner",
            timestamp=task.updated_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
        )
        iteration_limit = min(
            max_iterations or self.runtime.config.max_controller_iterations,
            self.runtime.config.max_controller_iterations,
        )

        for _ in range(iteration_limit):
            task = self.runtime.store.get_task(task_id)
            if task.terminal:
                return task
            if self._deadline_expired(task):
                return self._time_out(task, phase="before_planning")

            pending = task.memory.get("pending_proposal")
            replaying_approved_proposal = bool(pending and task.memory.get("approved_pending_call"))
            if replaying_approved_proposal:
                proposal = AgentProposal.model_validate(pending)
                approval_reference = str(task.memory["approved_pending_call"])
                assert proposal.call is not None
                proposal = proposal.model_copy(
                    update={
                        "call": proposal.call.model_copy(
                            update={"approval_reference": approval_reference}
                        )
                    }
                )
                memory = dict(task.memory)
                memory.pop("pending_proposal", None)
                memory.pop("approved_pending_call", None)
                task = self._save(task, memory=memory)
            else:
                try:
                    proposal = self.runtime.planner.propose(
                        task,
                        self.runtime.store.list_events(task_id),
                        self.runtime.tools.specs(),
                    )
                except PlannerError as exc:
                    failed = self.runtime.store.append_event(
                        task_id,
                        "planner.failed",
                        {"error": str(exc)},
                    )
                    self._record_activity(
                        run_id=task_id,
                        event_type="run_failed",
                        summary="The run failed while preparing the next bounded action.",
                        run_state="failed",
                        source="planner",
                        timestamp=task.updated_at,
                        role_id=task.permission_manifest.role_id,
                        skill_id=task.permission_manifest.skill_id,
                        audit_reference=failed.event_sha256,
                        error_code="planner_failed",
                        error_message=str(exc),
                    )
                    return self._save(
                        task,
                        status=TaskStatus.FAILED,
                        paused_reason=f"Planner failure: {exc}",
                    )

                interrupted = self._interruption_checkpoint(task)
                if interrupted is not None:
                    return interrupted

            if replaying_approved_proposal:
                resumed = self.runtime.store.append_event(
                    task_id,
                    "approval.resumed",
                    proposal.model_dump(mode="json"),
                )
                self._record_activity(
                    run_id=task_id,
                    event_type="approval_granted",
                    summary="A recorded approval resumed the bounded run.",
                    run_state="planning",
                    source="approval",
                    timestamp=resumed.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    audit_reference=resumed.event_sha256,
                )
            else:
                proposed = self.runtime.store.append_event(
                    task_id,
                    "planner.proposed",
                    proposal.model_dump(mode="json"),
                )
                self._record_activity(
                    run_id=task_id,
                    event_type="plan_proposed",
                    summary="The planner proposed the next bounded action.",
                    run_state="planning",
                    source="planner",
                    timestamp=proposed.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    tool_id=proposal.call.tool_id if proposal.call else None,
                    audit_reference=proposed.event_sha256,
                )
                task = self._advance_step(task)

            if proposal.kind == ProposalKind.COMPLETE:
                completed = self.runtime.store.append_event(
                    task_id,
                    "task.completed",
                    {"final_summary": proposal.final_summary},
                )
                self._record_activity(
                    run_id=task_id,
                    event_type="run_completed",
                    summary="The bounded run completed successfully.",
                    run_state="completed",
                    source="runtime",
                    timestamp=completed.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    audit_reference=completed.event_sha256,
                )
                return self._save(
                    task,
                    status=TaskStatus.COMPLETED,
                    final_summary=proposal.final_summary,
                    paused_reason=None,
                )
            if proposal.kind == ProposalKind.PAUSE:
                paused = self.runtime.store.append_event(
                    task_id,
                    "task.paused",
                    {"reason": proposal.pause_reason},
                )
                self._record_activity(
                    run_id=task_id,
                    event_type="run_paused",
                    summary="The bounded run paused and requires human attention.",
                    run_state="paused",
                    source="runtime",
                    timestamp=paused.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    audit_reference=paused.event_sha256,
                    metadata={"reason": proposal.pause_reason or ""},
                )
                return self._save(
                    task,
                    status=TaskStatus.PAUSED_OPERATOR,
                    paused_reason=proposal.pause_reason,
                )

            assert proposal.call is not None
            try:
                tool_spec = self.runtime.tools.get(proposal.call.tool_id).spec
            except ToolRegistryError:
                tool_spec = None
            self._record_activity(
                run_id=task_id,
                event_type="policy_check_started",
                summary="The bounded runtime is validating the proposed action against policy.",
                run_state="checking_policy",
                source="policy",
                timestamp=task.updated_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                tool_id=proposal.call.tool_id,
            )
            decision = self.policy.evaluate(task, proposal, tool_spec)
            decided = self.runtime.store.append_event(
                task_id,
                "policy.decided",
                decision.model_dump(mode="json"),
            )

            if decision.status == PolicyStatus.DENIED:
                self._record_activity(
                    run_id=task_id,
                    event_type="run_blocked",
                    summary="Policy blocked the proposed bounded action.",
                    run_state="blocked",
                    source="policy",
                    timestamp=decided.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    tool_id=proposal.call.tool_id,
                    policy_outcome="denied",
                    execution_state="blocked",
                    audit_reference=decided.event_sha256,
                    error_message=decision.reason,
                )
                return self._save(
                    task,
                    status=TaskStatus.BLOCKED,
                    paused_reason=decision.reason,
                )
            if decision.status == PolicyStatus.REQUIRES_APPROVAL:
                memory = dict(task.memory)
                memory["pending_proposal"] = proposal.model_dump(mode="json")
                approval_required = self.runtime.store.append_event(
                    task_id,
                    "approval.required",
                    {
                        "proposal_sha256": proposal.fingerprint(),
                        "reason": decision.reason,
                    },
                )
                self._record_activity(
                    run_id=task_id,
                    event_type="approval_requested",
                    summary="The proposed action requires explicit human approval.",
                    run_state="awaiting_approval",
                    source="approval",
                    timestamp=approval_required.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    tool_id=proposal.call.tool_id,
                    policy_outcome="requires_approval",
                    approval_requirement="required",
                    approval_state="pending",
                    audit_reference=approval_required.event_sha256,
                    error_message=decision.reason,
                )
                self._record_activity(
                    run_id=task_id,
                    event_type="run_paused",
                    summary="The bounded run paused while waiting for human approval.",
                    run_state="awaiting_approval",
                    source="approval",
                    timestamp=approval_required.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    tool_id=proposal.call.tool_id,
                    policy_outcome="requires_approval",
                    approval_requirement="required",
                    approval_state="pending",
                    audit_reference=approval_required.event_sha256,
                )
                return self._save(
                    task,
                    status=TaskStatus.PAUSED_APPROVAL,
                    memory=memory,
                    paused_reason=decision.reason,
                )

            self._record_activity(
                run_id=task_id,
                event_type="policy_allowed",
                summary="Policy allowed the proposed bounded action.",
                run_state="executing",
                source="policy",
                timestamp=decided.created_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                tool_id=proposal.call.tool_id,
                policy_outcome="allowed",
                audit_reference=decided.event_sha256,
            )
            assert tool_spec is not None
            if self._deadline_expired(task):
                return self._time_out(task, phase="before_tool_execution")
            self._record_activity(
                run_id=task_id,
                event_type="tool_execution_started",
                summary="An approved tool execution started.",
                run_state="executing",
                source="tool",
                timestamp=task.updated_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                tool_id=proposal.call.tool_id,
                execution_state="running",
            )
            try:
                result = self.runtime.tools.execute(task, proposal.call)
            except ToolRegistryError as exc:
                tool_error = self.runtime.store.append_event(
                    task_id,
                    "tool.registry_error",
                    {"error": str(exc)},
                )
                self._record_activity(
                    run_id=task_id,
                    event_type="run_blocked",
                    summary="The approved tool could not execute safely.",
                    run_state="blocked",
                    source="tool",
                    timestamp=tool_error.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    tool_id=proposal.call.tool_id,
                    execution_state="blocked",
                    audit_reference=tool_error.event_sha256,
                    error_code="tool_registry_error",
                    error_message=str(exc),
                )
                return self._save(
                    task,
                    status=TaskStatus.BLOCKED,
                    paused_reason=str(exc),
                )

            task = self._save(task, tool_call_count=task.tool_call_count + 1)
            executed = self.runtime.store.append_event(
                task_id,
                "tool.executed",
                {
                    "call": proposal.call.model_dump(mode="json"),
                    "result": result.model_dump(mode="json"),
                },
            )
            self._record_activity(
                run_id=task_id,
                event_type=(
                    "tool_execution_completed" if result.success else "tool_execution_failed"
                ),
                summary=(
                    "The approved tool execution completed."
                    if result.success
                    else "The approved tool execution failed."
                ),
                run_state="executing",
                source="tool",
                timestamp=executed.created_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                tool_id=proposal.call.tool_id,
                execution_state="succeeded" if result.success else "failed",
                audit_reference=executed.event_sha256,
                error_type=result.error_type,
                error_message=result.error_message,
                metadata={"evidence_sha256": result.evidence_sha256},
            )
            self._record_activity(
                run_id=task_id,
                event_type="evaluation_started",
                summary="The runtime started evaluating the tool result.",
                run_state="evaluating",
                source="evaluator",
                timestamp=executed.created_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                tool_id=proposal.call.tool_id,
            )
            evaluation = self.runtime.evaluator.evaluate(proposal.call, result)
            evaluated = self.runtime.store.append_event(
                task_id,
                "result.evaluated",
                evaluation.model_dump(mode="json"),
            )
            self._record_activity(
                run_id=task_id,
                event_type="evaluation_completed",
                summary="The runtime finished evaluating the tool result.",
                run_state="evaluating",
                source="evaluator",
                timestamp=evaluated.created_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                tool_id=proposal.call.tool_id,
                audit_reference=evaluated.event_sha256,
                metadata={"status": evaluation.status.value},
            )

            if result.success:
                memory = dict(task.memory)
                memory["last_tool_output"] = result.output
                memory["last_tool_evidence_sha256"] = result.evidence_sha256
                task = self._save(task, memory=memory)
                continue

            if evaluation.status == EvaluationStatus.RETRY:
                assert evaluation.failure_fingerprint is not None
                counts = dict(task.failure_counts)
                count = counts.get(evaluation.failure_fingerprint, 0) + 1
                counts[evaluation.failure_fingerprint] = count
                task = self._save(task, failure_counts=counts)
                if count >= task.permission_manifest.max_identical_failures:
                    stopped = self.runtime.store.append_event(
                        task_id,
                        "recovery.stopped",
                        {
                            "failure_fingerprint": evaluation.failure_fingerprint,
                            "count": count,
                        },
                    )
                    self._record_activity(
                        run_id=task_id,
                        event_type="run_blocked",
                        summary="The run blocked after repeated materially identical failures.",
                        run_state="blocked",
                        source="evaluator",
                        timestamp=stopped.created_at,
                        role_id=task.permission_manifest.role_id,
                        skill_id=task.permission_manifest.skill_id,
                        tool_id=proposal.call.tool_id,
                        execution_state="blocked",
                        audit_reference=stopped.event_sha256,
                        error_message="Repeated materially identical failure limit reached.",
                    )
                    return self._save(
                        task,
                        status=TaskStatus.BLOCKED,
                        paused_reason="Repeated materially identical failure limit reached.",
                    )
                self._record_activity(
                    run_id=task_id,
                    event_type="retry_scheduled",
                    summary="The runtime scheduled a safe retry for the bounded action.",
                    run_state="planning",
                    source="evaluator",
                    timestamp=evaluated.created_at,
                    role_id=task.permission_manifest.role_id,
                    skill_id=task.permission_manifest.skill_id,
                    tool_id=proposal.call.tool_id,
                    audit_reference=evaluated.event_sha256,
                )
                continue

            self._record_activity(
                run_id=task_id,
                event_type="run_failed",
                summary="The bounded run failed after evaluating the tool result.",
                run_state="failed",
                source="evaluator",
                timestamp=evaluated.created_at,
                role_id=task.permission_manifest.role_id,
                skill_id=task.permission_manifest.skill_id,
                tool_id=proposal.call.tool_id,
                audit_reference=evaluated.event_sha256,
                error_message=evaluation.reason,
            )
            return self._save(
                task,
                status=TaskStatus.FAILED,
                paused_reason=evaluation.reason,
            )

        task = self.runtime.store.get_task(task_id)
        paused = self.runtime.store.append_event(
            task_id,
            "budget.paused",
            {"iteration_limit": iteration_limit},
        )
        self._record_activity(
            run_id=task_id,
            event_type="run_paused",
            summary="The bounded run paused after reaching the controller iteration budget.",
            run_state="paused",
            source="runtime",
            timestamp=paused.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            audit_reference=paused.event_sha256,
        )
        return self._save(
            task,
            status=TaskStatus.PAUSED_BUDGET,
            paused_reason="Controller iteration budget reached.",
        )

    def approve_and_resume(self, task_id: str) -> AgentTask:
        task = self.runtime.store.get_task(task_id)
        if task.status != TaskStatus.PAUSED_APPROVAL:
            raise ValueError("Task is not waiting for approval")
        if self._deadline_expired(task):
            return self._time_out(task, phase="before_approval_resume")
        binding = task.approval_binding
        service = self.runtime.approval_service
        if binding is None or service is None:
            raise ValueError("authoritative Approval Centre integration is unavailable")
        consumed = service.consume(
            request_id=binding.request_id,
            manifest=binding.action_manifest,
            execution_id=binding.execution_id,
            actor_id=binding.consumer_actor_id,
            execution_plan=binding.execution_plan,
        )
        memory = dict(task.memory)
        memory["approved_pending_call"] = consumed.fingerprint()
        memory["consumed_approval_sha256"] = consumed.fingerprint()
        recorded = self.runtime.store.append_event(
            task_id,
            "approval.recorded",
            {
                "approval_request_id": consumed.request_id,
                "consumed_approval_sha256": consumed.fingerprint(),
            },
        )
        self._record_activity(
            run_id=task_id,
            event_type="approval_granted",
            summary="A human operator recorded the required approval reference.",
            run_state="awaiting_approval",
            source="approval",
            timestamp=recorded.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            approval_requirement="required",
            approval_state="granted",
            audit_reference=recorded.event_sha256,
        )
        task = self._save(task, memory=memory, status=TaskStatus.RUNNING)
        return self.run(task.task_id)

    @staticmethod
    def _validate_approval_binding(
        permission_manifest: PermissionManifest,
        binding: AgentApprovalBinding,
        task_id: str,
    ) -> None:
        manifest = binding.action_manifest
        plan = binding.execution_plan
        if binding.execution_id != task_id:
            raise ValueError("approval execution_id must match the agent task_id")
        if manifest.role_id != permission_manifest.role_id:
            raise ValueError("approval manifest role does not match task permissions")
        if manifest.skill_id != permission_manifest.skill_id:
            raise ValueError("approval manifest skill does not match task permissions")
        if manifest.action not in permission_manifest.allowed_actions:
            raise ValueError("approval manifest action is not allowed by task permissions")
        if manifest.tool_id not in permission_manifest.allowed_tools:
            raise ValueError("approval manifest tool is not allowed by task permissions")
        if plan.runtime_budget_seconds > permission_manifest.maximum_runtime_seconds:
            raise ValueError("approval execution runtime exceeds task permissions")

    def cancel(self, task_id: str, reason: str) -> AgentTask:
        task = self.runtime.store.get_task(task_id)
        if task.terminal:
            return task
        memory = task.memory
        workflow = memory.get("assessment_workflow")
        if isinstance(workflow, dict):
            memory = {
                **memory,
                "assessment_workflow": {
                    **workflow,
                    "workflow_state": "cancelled",
                    "blocking_reason": reason,
                },
            }
        cancelled_task = self._save(
            task,
            status=TaskStatus.CANCELLED,
            paused_reason=reason,
            memory=memory,
        )
        cancelled = self.runtime.store.append_event(task_id, "task.cancelled", {"reason": reason})
        self._record_activity(
            run_id=task_id,
            event_type="run_stopped",
            summary="A human operator recorded a cancellation for the bounded run.",
            run_state="cancelled",
            source="operator",
            timestamp=cancelled.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            execution_state="cancelled",
            audit_reference=cancelled.event_sha256,
            metadata={"reason": reason},
        )
        return cancelled_task

    def pause(self, task_id: str, reason: str) -> AgentTask:
        if not reason.strip():
            raise ValueError("pause reason must not be empty")
        task = self.runtime.store.get_task(task_id)
        if task.terminal or task.status == TaskStatus.PAUSED_OPERATOR:
            return task
        if task.status == TaskStatus.PAUSED_APPROVAL:
            raise ValueError("approval-paused tasks require an approval decision")
        paused_task = self._save(
            task,
            status=TaskStatus.PAUSED_OPERATOR,
            paused_reason=reason.strip(),
        )
        paused = self.runtime.store.append_event(
            task_id,
            "task.operator_paused",
            {"reason": reason.strip()},
        )
        self._record_activity(
            run_id=task_id,
            event_type="run_paused",
            summary="A human operator paused the bounded run.",
            run_state="paused",
            source="operator",
            timestamp=paused.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            audit_reference=paused.event_sha256,
            metadata={"reason": reason.strip()},
        )
        return paused_task

    def resume(self, task_id: str) -> AgentTask:
        task = self.runtime.store.get_task(task_id)
        if task.status != TaskStatus.PAUSED_OPERATOR:
            raise ValueError("Task is not paused by an operator")
        if self._deadline_expired(task):
            return self._time_out(task, phase="before_operator_resume")
        resumed = self.runtime.store.append_event(task_id, "task.operator_resumed", {})
        self._record_activity(
            run_id=task_id,
            event_type="run_resumed",
            summary="A human operator resumed the bounded run.",
            run_state="planning",
            source="operator",
            timestamp=resumed.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            audit_reference=resumed.event_sha256,
        )
        task = self._save(task, status=TaskStatus.RUNNING, paused_reason=None)
        return self.run(task.task_id)

    def report(self, task_id: str) -> ExecutionReport:
        task = self.runtime.store.get_task(task_id)
        events = self.runtime.store.list_events(task_id)
        final_hash = self.runtime.store.verify_integrity(task_id)
        payload: dict[str, Any] = {
            "task_id": task.task_id,
            "status": task.status,
            "objective": task.objective,
            "step_count": task.step_count,
            "tool_call_count": task.tool_call_count,
            "event_count": len(events),
            "final_event_sha256": final_hash,
            "permission_manifest_sha256": task.permission_manifest.fingerprint(),
            "final_summary": task.final_summary,
            "paused_reason": task.paused_reason,
        }
        return ExecutionReport(**payload, report_sha256=sha256_json(payload))

    def _advance_step(self, task: AgentTask) -> AgentTask:
        memory = dict(task.memory)
        memory["planner_cursor"] = int(memory.get("planner_cursor", 0)) + 1
        return self._save(task, step_count=task.step_count + 1, memory=memory)

    def _save(self, task: AgentTask, **changes: Any) -> AgentTask:
        changes.setdefault("updated_at", self._now())
        evolved = task.evolved(**changes)
        self.runtime.store.save_task(evolved, expected_revision=task.revision)
        return evolved

    def _now(self) -> datetime:
        value = self.runtime.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("agent runtime clock must return a timezone-aware timestamp")
        return value.astimezone(UTC)

    def _deadline_expired(self, task: AgentTask) -> bool:
        assert task.deadline_at is not None
        return self._now() >= task.deadline_at

    def _interruption_checkpoint(self, task: AgentTask) -> AgentTask | None:
        current = self.runtime.store.get_task(task.task_id)
        if current.revision == task.revision:
            return None
        if current.terminal or current.status == TaskStatus.PAUSED_OPERATOR:
            return current
        raise RuntimeError("Agent task changed unexpectedly during planning")

    def _time_out(self, task: AgentTask, *, phase: str) -> AgentTask:
        assert task.deadline_at is not None
        timed_out = self.runtime.store.append_event(
            task.task_id,
            "task.timed_out",
            {"deadline_at": task.deadline_at.isoformat(), "phase": phase},
            created_at=self._now(),
        )
        self._record_activity(
            run_id=task.task_id,
            event_type="run_failed",
            summary="The bounded run reached its immutable runtime deadline.",
            run_state="failed",
            source="runtime",
            timestamp=timed_out.created_at,
            role_id=task.permission_manifest.role_id,
            skill_id=task.permission_manifest.skill_id,
            execution_state="failed",
            audit_reference=timed_out.event_sha256,
            error_code="runtime_deadline_expired",
            error_message="The immutable task runtime deadline expired.",
            metadata={"phase": phase},
        )
        memory = task.memory
        workflow = memory.get("assessment_workflow")
        if isinstance(workflow, dict):
            memory = {
                **memory,
                "assessment_workflow": {
                    **workflow,
                    "workflow_state": "timed_out",
                    "blocking_reason": "Immutable task runtime deadline expired.",
                },
            }
        return self._save(
            task,
            status=TaskStatus.TIMED_OUT,
            paused_reason="Immutable task runtime deadline expired.",
            memory=memory,
        )

    @staticmethod
    def _objective_reference(objective: str) -> str:
        return hashlib.sha256(objective.encode("utf-8")).hexdigest()

    def _record_activity(
        self,
        *,
        run_id: str,
        event_type: str,
        summary: str,
        run_state: str,
        source: str,
        timestamp,
        role_id: str | None = None,
        skill_id: str | None = None,
        tool_id: str | None = None,
        policy_outcome: str = "not_checked",
        approval_requirement: str = "not_required",
        approval_state: str = "not_applicable",
        execution_state: str = "not_started",
        audit_reference: str | None = None,
        error_code: str | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        activity = self.runtime.activity_service
        if activity is None:
            return
        final_error_code = error_code or error_type
        activity.record_transition(
            run_id=run_id,
            timestamp=timestamp,
            event_type=event_type,
            summary=summary,
            run_state=run_state,
            source=source,
            role_id=role_id,
            skill_id=skill_id,
            tool_id=tool_id,
            policy_outcome=policy_outcome,
            approval_requirement=approval_requirement,
            approval_state=approval_state,
            execution_state=execution_state,
            audit_reference=audit_reference,
            error_code=final_error_code,
            error_message=error_message,
            metadata=metadata or {},
        )
