from __future__ import annotations

from vulnhunter.agent.controller import AgentController, AgentRuntime
from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import (
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


def controller(tmp_path, proposals, handler, **spec_overrides) -> AgentController:
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
            planner=SequencePlanner(proposals),
            tools=registry,
            evaluator=ResultEvaluator(),
        )
    )


def create(value: AgentController, permission=None):
    return value.create_task(
        task_id="task-controller",
        objective="Perform an approved bounded local evidence task.",
        permission_manifest=permission or manifest(),
    )


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
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: calls.append(arguments) or {},
    )
    create(value, manifest(approval_required_actions=("evidence.inspect",)))
    task = value.run("task-controller")
    assert task.status == TaskStatus.PAUSED_APPROVAL
    assert calls == []


def test_approval_resume_executes_pending_call_and_completes(tmp_path) -> None:
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {"approved": True},
    )
    create(value, manifest(approval_required_actions=("evidence.inspect",)))
    value.run("task-controller")
    task = value.approve_and_resume("task-controller", "approval-123")
    assert task.status == TaskStatus.COMPLETED
    assert task.tool_call_count == 1


def test_empty_approval_reference_is_rejected(tmp_path) -> None:
    value = controller(
        tmp_path,
        (tool_proposal(), complete_proposal()),
        lambda arguments, context: {},
    )
    create(value, manifest(approval_required_actions=("evidence.inspect",)))
    value.run("task-controller")
    try:
        value.approve_and_resume("task-controller", " ")
    except ValueError as exc:
        assert "must not be empty" in str(exc)
    else:
        raise AssertionError("empty approval reference should fail")


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
