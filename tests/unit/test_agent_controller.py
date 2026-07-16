from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.actions.models import ActionClass, ActionManifest, ExecutionLimits
from vulnhunter.agent.controller import AgentController, AgentRuntime
from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import (
    AgentApprovalBinding,
    AgentProposal,
    PermissionManifest,
    ProposalKind,
    RuntimeConfig,
    TaskStatus,
    ToolCall,
    ToolRisk,
    ToolSpec,
)
from vulnhunter.agent.planner import SequencePlanner
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent.tools import ToolExecutionError, ToolRegistry
from vulnhunter.approvals.conditions import CanonicalApprovalExecutionPlan
from vulnhunter.approvals.models import ApprovalDecision
from vulnhunter.approvals.service import ApprovalService
from vulnhunter.approvals.store import ApprovalStore


def tool_proposal(*, approval_reference=None) -> AgentProposal:
    return AgentProposal(
        kind=ProposalKind.TOOL,
        rationale="Inspect approved local evidence",
        call=ToolCall(
            tool_id="agent.echo",
            action="evidence.inspect",
            operation="echo",
            arguments={"value": "ok"},
            approval_reference=approval_reference,
        ),
    )


def complete_proposal() -> AgentProposal:
    return AgentProposal(
        kind=ProposalKind.COMPLETE,
        rationale="The bounded objective is complete",
        final_summary="Completed safely",
    )


def manifest(**overrides) -> PermissionManifest:
    values = {
        "manifest_id": "manifest-controller",
        "role_id": "orchestrator",
        "allowed_actions": ("evidence.inspect",),
        "allowed_tools": ("agent.echo",),
        "allowed_risks": (ToolRisk.READ_ONLY,),
    }
    values.update(overrides)
    return PermissionManifest(**values)


def controller(
    tmp_path,
    proposals,
    handler,
    *,
    clock=None,
    planner=None,
    approval_service=None,
    **spec_overrides,
) -> AgentController:
    registry = ToolRegistry()
    values = {
        "tool_id": "agent.echo",
        "action": "evidence.inspect",
        "operation": "echo",
        "description": "Echo approved local evidence.",
        "risk": ToolRisk.READ_ONLY,
    }
    values.update(spec_overrides)
    registry.register(ToolSpec(**values), handler)
    return AgentController(
        AgentRuntime(
            config=RuntimeConfig(),
            store=AgentStore(tmp_path / "agent.db"),
            planner=planner or SequencePlanner(proposals),
            tools=registry,
            evaluator=ResultEvaluator(),
            approval_service=approval_service,
            **({"clock": clock} if clock is not None else {}),
        )
    )


def create(value: AgentController, permission=None, approval_binding=None):
    return value.create_task(
        task_id="task-controller",
        objective="Perform an approved bounded local evidence task.",
        permission_manifest=permission or manifest(),
        approval_binding=approval_binding,
    )


def governed_approval(tmp_path):
    instant = datetime.now(UTC)
    action_manifest = ActionManifest(
        manifest_id="manifest-action",
        campaign_id="campaign-agent",
        requested_by="requester-agent",
        role_id="orchestrator",
        skill_id="bounded-task-routing",
        action="evidence.inspect",
        action_class=ActionClass.CONSEQUENTIAL,
        tool_id="agent.echo",
        operation="echo",
        target_references=("target-local",),
        authorization_references=("authorization-local",),
        limits=ExecutionLimits(
            timeout_seconds=60,
            maximum_requests=1,
            maximum_output_bytes=1024,
        ),
        approval_required=True,
        created_at=instant,
        expires_at=instant + timedelta(minutes=10),
        purpose="Inspect governed local evidence.",
    )
    plan = CanonicalApprovalExecutionPlan(
        execution_id="task-controller",
        action_manifest_sha256=action_manifest.fingerprint(),
        target_identifiers=action_manifest.target_references,
        selected_tool=action_manifest.tool_id,
        selected_profile="safe-local",
        request_budget=1,
        runtime_budget_seconds=60,
        output_budget_bytes=1024,
        adapter_identity="agent-echo-adapter",
    )
    service = ApprovalService(ApprovalStore(tmp_path / "approvals.db"))
    service.request(
        request_id="approval-agent",
        run_id="task-controller",
        manifest=action_manifest,
        summary="Approve one bounded evidence inspection.",
        risk_summary="Local read-only tool execution requires review.",
    )
    service.decide(
        request_id="approval-agent",
        actor_id="approver-agent",
        decision=ApprovalDecision.APPROVE_ONCE,
        reason="Approved after reviewing the exact manifest and local target.",
    )
    binding = AgentApprovalBinding(
        request_id="approval-agent",
        execution_id="task-controller",
        consumer_actor_id="executor-agent",
        action_manifest=action_manifest,
        execution_plan=plan,
    )
    return service, binding


def test_successful_loop_executes_and_completes(tmp_path) -> None:
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {"value": arguments["value"]},
    )
    create(value)
    task = value.run("task-controller")
    assert task.status == TaskStatus.COMPLETED
    assert task.tool_call_count == 1
    assert task.memory["last_tool_output"] == {"value": "ok"}


def test_denied_action_blocks_before_execution(tmp_path) -> None:
    calls = []
    value = controller(
        tmp_path,
        (tool_proposal(),),
        lambda arguments, context: calls.append(arguments) or {},
    )
    create(value, manifest(allowed_actions=("other.action",)))
    task = value.run("task-controller")
    assert task.status == TaskStatus.BLOCKED
    assert calls == []


def test_approval_required_pauses_before_execution(tmp_path) -> None:
    calls = []
    service, binding = governed_approval(tmp_path)
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: calls.append(arguments) or {},
        approval_service=service,
    )
    create(
        value,
        manifest(
            skill_id="bounded-task-routing",
            approval_required_actions=("evidence.inspect",),
        ),
        binding,
    )
    task = value.run("task-controller")
    assert task.status == TaskStatus.PAUSED_APPROVAL
    assert calls == []


def test_approval_resume_executes_pending_call_and_completes(tmp_path) -> None:
    service, binding = governed_approval(tmp_path)
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {"approved": True},
        approval_service=service,
    )
    create(
        value,
        manifest(
            skill_id="bounded-task-routing",
            approval_required_actions=("evidence.inspect",),
        ),
        binding,
    )
    value.run("task-controller")
    task = value.approve_and_resume("task-controller")
    assert task.status == TaskStatus.COMPLETED
    assert task.tool_call_count == 1


def test_missing_approval_service_fails_closed(tmp_path) -> None:
    _, binding = governed_approval(tmp_path)
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {},
    )
    create(
        value,
        manifest(
            skill_id="bounded-task-routing",
            approval_required_actions=("evidence.inspect",),
        ),
        binding,
    )
    value.run("task-controller")
    try:
        value.approve_and_resume("task-controller")
    except ValueError as exc:
        assert "integration is unavailable" in str(exc)
    else:
        raise AssertionError("missing Approval Centre must fail closed")


def test_planner_supplied_approval_reference_cannot_authorize_execution(tmp_path) -> None:
    calls = []
    value = controller(
        tmp_path,
        (tool_proposal(approval_reference="forged-reference"),),
        lambda arguments, context: calls.append(arguments) or {},
    )
    create(value, manifest(approval_required_actions=("evidence.inspect",)))

    task = value.run("task-controller")

    assert task.status == TaskStatus.BLOCKED
    assert "not produced" in (task.paused_reason or "")
    assert calls == []


def test_retryable_failure_can_recover(tmp_path) -> None:
    attempts = {"count": 0}

    def handler(arguments, context):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise ToolExecutionError("temporary", retryable=True)
        return {"recovered": True}

    value = controller(
        tmp_path,
        (tool_proposal(), tool_proposal(), complete_proposal()),
        handler,
    )
    create(value)
    task = value.run("task-controller")
    assert task.status == TaskStatus.COMPLETED
    assert attempts["count"] == 2


def test_identical_failure_twice_blocks(tmp_path) -> None:
    def handler(arguments, context):
        raise ToolExecutionError("same failure", retryable=True)

    value = controller(tmp_path, (tool_proposal(), tool_proposal()), handler)
    create(value)
    task = value.run("task-controller")
    assert task.status == TaskStatus.BLOCKED
    assert "Repeated materially identical" in (task.paused_reason or "")


def test_nonretryable_failure_fails_task(tmp_path) -> None:
    def handler(arguments, context):
        raise ToolExecutionError("permanent", retryable=False)

    value = controller(tmp_path, (tool_proposal(),), handler)
    create(value)
    task = value.run("task-controller")
    assert task.status == TaskStatus.FAILED


def test_iteration_budget_pauses(tmp_path) -> None:
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {},
    )
    create(value)
    task = value.run("task-controller", max_iterations=1)
    assert task.status == TaskStatus.PAUSED_BUDGET


def test_iteration_budget_checkpoint_can_resume(tmp_path) -> None:
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {},
    )
    create(value)
    paused = value.run("task-controller", max_iterations=1)
    assert paused.status == TaskStatus.PAUSED_BUDGET
    completed = value.run("task-controller")
    assert completed.status == TaskStatus.COMPLETED


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class AdvancingPlanner:
    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock

    def propose(self, task, events, tools):
        self.clock.advance(2)
        return tool_proposal()


class InterruptingPlanner:
    def __init__(self, interrupt) -> None:
        self.interrupt = interrupt

    def propose(self, task, events, tools):
        self.interrupt()
        return tool_proposal()


def test_expired_task_stops_before_planning(tmp_path) -> None:
    calls = []
    clock = MutableClock()
    value = controller(
        tmp_path,
        (complete_proposal(),),
        lambda arguments, context: calls.append(arguments) or {},
        clock=clock,
    )
    create(value, manifest(maximum_runtime_seconds=1))
    clock.advance(2)

    task = value.run("task-controller")

    assert task.status == TaskStatus.TIMED_OUT
    assert task.step_count == 0
    assert calls == []
    events = value.runtime.store.list_events(task.task_id)
    assert events[-1].event_type == "task.timed_out"
    assert events[-1].payload["phase"] == "before_planning"


def test_expired_task_stops_before_tool_invocation(tmp_path) -> None:
    calls = []
    clock = MutableClock()
    value = controller(
        tmp_path,
        (),
        lambda arguments, context: calls.append(arguments) or {},
        clock=clock,
        planner=AdvancingPlanner(clock),
    )
    create(value, manifest(maximum_runtime_seconds=1))

    task = value.run("task-controller")

    assert task.status == TaskStatus.TIMED_OUT
    assert task.step_count == 1
    assert task.tool_call_count == 0
    assert calls == []
    events = value.runtime.store.list_events(task.task_id)
    assert events[-1].event_type == "task.timed_out"
    assert events[-1].payload["phase"] == "before_tool_execution"


def test_approval_resume_rejects_completed_task_before_deadline_check(tmp_path) -> None:
    clock = MutableClock()
    value = controller(
        tmp_path,
        (complete_proposal(),),
        lambda arguments, context: {},
        clock=clock,
    )
    create(value, manifest(maximum_runtime_seconds=1))
    completed = value.run("task-controller")
    assert completed.status == TaskStatus.COMPLETED
    clock.advance(2)

    try:
        value.approve_and_resume("task-controller")
    except ValueError as exc:
        assert "not waiting for approval" in str(exc)
    else:
        raise AssertionError("completed task must reject approval resume")


def test_operator_pause_and_resume_complete_from_checkpoint(tmp_path) -> None:
    value = controller(
        tmp_path,
        (complete_proposal(),),
        lambda arguments, context: {},
    )
    create(value)
    paused = value.pause("task-controller", "operator review")
    assert paused.status == TaskStatus.PAUSED_OPERATOR
    assert value.run("task-controller").status == TaskStatus.PAUSED_OPERATOR

    completed = value.resume("task-controller")
    assert completed.status == TaskStatus.COMPLETED


def test_concurrent_operator_pause_wins_before_tool_execution(tmp_path) -> None:
    calls = []
    holder = {}
    planner = InterruptingPlanner(
        lambda: holder["controller"].pause("task-controller", "inspect plan")
    )
    value = controller(
        tmp_path,
        (),
        lambda arguments, context: calls.append(arguments) or {},
        planner=planner,
    )
    holder["controller"] = value
    create(value)

    task = value.run("task-controller")

    assert task.status == TaskStatus.PAUSED_OPERATOR
    assert calls == []


def test_concurrent_cancel_wins_before_tool_execution(tmp_path) -> None:
    calls = []
    holder = {}
    planner = InterruptingPlanner(
        lambda: holder["controller"].cancel("task-controller", "operator cancel")
    )
    value = controller(
        tmp_path,
        (),
        lambda arguments, context: calls.append(arguments) or {},
        planner=planner,
    )
    holder["controller"] = value
    create(value)

    task = value.run("task-controller")

    assert task.status == TaskStatus.CANCELLED
    assert calls == []


def test_cancel_records_terminal_state(tmp_path) -> None:
    value = controller(
        tmp_path,
        (complete_proposal(),),
        lambda arguments, context: {},
    )
    create(value)
    task = value.cancel("task-controller", "operator request")
    assert task.status == TaskStatus.CANCELLED


def test_report_verifies_audit_chain(tmp_path) -> None:
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {"value": "ok"},
    )
    create(value)
    value.run("task-controller")
    report = value.report("task-controller")
    assert report.status == TaskStatus.COMPLETED
    assert report.event_count > 0
    assert len(report.report_sha256) == 64
