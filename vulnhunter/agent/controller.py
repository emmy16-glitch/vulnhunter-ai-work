"""Bounded execution controller that owns the complete agent loop."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import (
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
)
from vulnhunter.agent.planner import Planner, PlannerError
from vulnhunter.agent.policy import AgentPolicyEngine
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent.tools import ToolRegistry, ToolRegistryError


@dataclass(frozen=True)
class AgentRuntime:
    """Dependencies for one controller instance."""

    config: RuntimeConfig
    store: AgentStore
    planner: Planner
    tools: ToolRegistry
    evaluator: ResultEvaluator


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
    ) -> AgentTask:
        task = AgentTask(
            task_id=task_id,
            objective=objective,
            permission_manifest=permission_manifest,
        )
        self.runtime.store.create_task(task)
        self.runtime.store.append_event(
            task.task_id,
            "task.created",
            {
                "objective": task.objective,
                "permission_manifest_sha256": permission_manifest.fingerprint(),
            },
        )
        return task

    def run(self, task_id: str, *, max_iterations: int | None = None) -> AgentTask:
        task = self.runtime.store.get_task(task_id)
        if task.terminal:
            return task
        if task.status == TaskStatus.PAUSED_APPROVAL and not task.memory.get(
            "approved_pending_call"
        ):
            return task

        task = self._save(task, status=TaskStatus.RUNNING, paused_reason=None)
        iteration_limit = min(
            max_iterations or self.runtime.config.max_controller_iterations,
            self.runtime.config.max_controller_iterations,
        )

        for _ in range(iteration_limit):
            task = self.runtime.store.get_task(task_id)
            if task.terminal:
                return task

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
                    self.runtime.store.append_event(
                        task_id,
                        "planner.failed",
                        {"error": str(exc)},
                    )
                    return self._save(
                        task,
                        status=TaskStatus.FAILED,
                        paused_reason=f"Planner failure: {exc}",
                    )

            if replaying_approved_proposal:
                self.runtime.store.append_event(
                    task_id,
                    "approval.resumed",
                    proposal.model_dump(mode="json"),
                )
            else:
                self.runtime.store.append_event(
                    task_id,
                    "planner.proposed",
                    proposal.model_dump(mode="json"),
                )
                task = self._advance_step(task)

            if proposal.kind == ProposalKind.COMPLETE:
                self.runtime.store.append_event(
                    task_id,
                    "task.completed",
                    {"final_summary": proposal.final_summary},
                )
                return self._save(
                    task,
                    status=TaskStatus.COMPLETED,
                    final_summary=proposal.final_summary,
                    paused_reason=None,
                )
            if proposal.kind == ProposalKind.PAUSE:
                self.runtime.store.append_event(
                    task_id,
                    "task.paused",
                    {"reason": proposal.pause_reason},
                )
                return self._save(
                    task,
                    status=TaskStatus.PAUSED_BUDGET,
                    paused_reason=proposal.pause_reason,
                )

            assert proposal.call is not None
            try:
                tool_spec = self.runtime.tools.get(proposal.call.tool_id).spec
            except ToolRegistryError:
                tool_spec = None
            decision = self.policy.evaluate(task, proposal, tool_spec)
            self.runtime.store.append_event(
                task_id,
                "policy.decided",
                decision.model_dump(mode="json"),
            )

            if decision.status == PolicyStatus.DENIED:
                return self._save(
                    task,
                    status=TaskStatus.BLOCKED,
                    paused_reason=decision.reason,
                )
            if decision.status == PolicyStatus.REQUIRES_APPROVAL:
                memory = dict(task.memory)
                memory["pending_proposal"] = proposal.model_dump(mode="json")
                self.runtime.store.append_event(
                    task_id,
                    "approval.required",
                    {
                        "proposal_sha256": proposal.fingerprint(),
                        "reason": decision.reason,
                    },
                )
                return self._save(
                    task,
                    status=TaskStatus.PAUSED_APPROVAL,
                    memory=memory,
                    paused_reason=decision.reason,
                )

            assert tool_spec is not None
            try:
                result = self.runtime.tools.execute(task, proposal.call)
            except ToolRegistryError as exc:
                self.runtime.store.append_event(
                    task_id,
                    "tool.registry_error",
                    {"error": str(exc)},
                )
                return self._save(
                    task,
                    status=TaskStatus.BLOCKED,
                    paused_reason=str(exc),
                )

            task = self._save(task, tool_call_count=task.tool_call_count + 1)
            self.runtime.store.append_event(
                task_id,
                "tool.executed",
                {
                    "call": proposal.call.model_dump(mode="json"),
                    "result": result.model_dump(mode="json"),
                },
            )
            evaluation = self.runtime.evaluator.evaluate(proposal.call, result)
            self.runtime.store.append_event(
                task_id,
                "result.evaluated",
                evaluation.model_dump(mode="json"),
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
                    self.runtime.store.append_event(
                        task_id,
                        "recovery.stopped",
                        {
                            "failure_fingerprint": evaluation.failure_fingerprint,
                            "count": count,
                        },
                    )
                    return self._save(
                        task,
                        status=TaskStatus.BLOCKED,
                        paused_reason="Repeated materially identical failure limit reached.",
                    )
                continue

            return self._save(
                task,
                status=TaskStatus.FAILED,
                paused_reason=evaluation.reason,
            )

        task = self.runtime.store.get_task(task_id)
        self.runtime.store.append_event(
            task_id,
            "budget.paused",
            {"iteration_limit": iteration_limit},
        )
        return self._save(
            task,
            status=TaskStatus.PAUSED_BUDGET,
            paused_reason="Controller iteration budget reached.",
        )

    def approve_and_resume(self, task_id: str, approval_reference: str) -> AgentTask:
        task = self.runtime.store.get_task(task_id)
        if task.status != TaskStatus.PAUSED_APPROVAL:
            raise ValueError("Task is not waiting for approval")
        if not approval_reference.strip():
            raise ValueError("approval_reference must not be empty")
        memory = dict(task.memory)
        memory["approved_pending_call"] = approval_reference.strip()
        self.runtime.store.append_event(
            task_id,
            "approval.recorded",
            {"approval_reference": approval_reference.strip()},
        )
        task = self._save(task, memory=memory, status=TaskStatus.RUNNING)
        return self.run(task.task_id)

    def cancel(self, task_id: str, reason: str) -> AgentTask:
        task = self.runtime.store.get_task(task_id)
        if task.terminal:
            return task
        self.runtime.store.append_event(task_id, "task.cancelled", {"reason": reason})
        return self._save(
            task,
            status=TaskStatus.CANCELLED,
            paused_reason=reason,
        )

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
        evolved = task.evolved(**changes)
        self.runtime.store.save_task(evolved, expected_revision=task.revision)
        return evolved
