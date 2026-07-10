from __future__ import annotations

import pytest

from vulnhunter.agent.models import (
    AgentProposal,
    AgentTask,
    PermissionManifest,
    ProposalKind,
    ToolSpec,
)
from vulnhunter.agent.planner import (
    CallableModelGateway,
    ModelPlanner,
    PlannerError,
    SequencePlanner,
)


def task() -> AgentTask:
    return AgentTask(
        task_id="task-planner",
        objective="Choose the next bounded action.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-planner",
            role_id="orchestrator",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
        ),
    )


def complete() -> AgentProposal:
    return AgentProposal(
        kind=ProposalKind.COMPLETE,
        rationale="Objective is complete",
        final_summary="Done",
    )


def test_sequence_planner_returns_current_cursor() -> None:
    planner = SequencePlanner((complete(),))
    assert planner.propose(task(), (), ()) == complete()


def test_sequence_planner_rejects_empty_plan() -> None:
    with pytest.raises(PlannerError, match="at least one"):
        SequencePlanner(())


def test_sequence_planner_stops_after_plan() -> None:
    planned_task = task().model_copy(update={"memory": {"planner_cursor": 1}})
    with pytest.raises(PlannerError, match="no remaining"):
        SequencePlanner((complete(),)).propose(planned_task, (), ())


def test_model_planner_validates_structured_response() -> None:
    gateway = CallableModelGateway(lambda request: complete().model_dump(mode="json"))
    proposal = ModelPlanner(gateway).propose(task(), (), ())
    assert proposal.kind == ProposalKind.COMPLETE


def test_model_planner_rejects_invalid_response() -> None:
    gateway = CallableModelGateway(lambda request: {"kind": "tool"})
    with pytest.raises(PlannerError, match="invalid proposal"):
        ModelPlanner(gateway).propose(task(), (), ())


def test_model_request_contains_state_and_tools() -> None:
    captured = {}

    def callback(request):
        captured.update(request)
        return complete().model_dump(mode="json")

    spec = ToolSpec(
        tool_id="agent.echo",
        action="evidence.inspect",
        operation="echo",
        description="Echo approved local evidence.",
    )
    ModelPlanner(CallableModelGateway(callback)).propose(task(), (), (spec,))
    assert captured["objective"] == task().objective
    assert captured["available_tools"][0]["tool_id"] == "agent.echo"
    assert captured["rules"]["no_direct_tool_execution"] is True
