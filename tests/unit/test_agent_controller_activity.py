from __future__ import annotations

from datetime import UTC, datetime

from vulnhunter.agent.controller import AgentController, AgentRuntime
from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import (
    AgentProposal,
    PermissionManifest,
    ProposalKind,
    RuntimeConfig,
    ToolCall,
    ToolRisk,
    ToolSpec,
)
from vulnhunter.agent.planner import SequencePlanner
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent.tools import ToolExecutionError, ToolRegistry
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore

NOW = datetime(2026, 7, 10, tzinfo=UTC)


def _controller(tmp_path):
    tools = ToolRegistry()
    tools.register(
        ToolSpec(
            tool_id="agent.echo",
            action="evidence.inspect",
            operation="echo",
            description="Echo approved local evidence.",
            risk=ToolRisk.READ_ONLY,
        ),
        lambda arguments, context: {"value": arguments["value"]},
    )
    return AgentController(
        AgentRuntime(
            config=RuntimeConfig(global_denied_actions=()),
            store=AgentStore(tmp_path / "agent.db"),
            planner=SequencePlanner(
                (
                    AgentProposal(
                        kind=ProposalKind.TOOL,
                        rationale="Inspect local evidence.",
                        call=ToolCall(
                            tool_id="agent.echo",
                            action="evidence.inspect",
                            operation="echo",
                            arguments={"value": "ok"},
                        ),
                    ),
                    AgentProposal(
                        kind=ProposalKind.COMPLETE,
                        rationale="The bounded objective completed.",
                        final_summary="Completed safely.",
                    ),
                )
            ),
            tools=tools,
            evaluator=ResultEvaluator(),
            activity_service=AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity")),
        )
    )


def test_controller_emits_activity_events_when_service_is_present(tmp_path) -> None:
    tools = ToolRegistry()
    tools.register(
        ToolSpec(
            tool_id="agent.echo",
            action="evidence.inspect",
            operation="echo",
            description="Echo approved local evidence.",
            risk=ToolRisk.READ_ONLY,
        ),
        lambda arguments, context: {"value": arguments["value"]},
    )
    controller = AgentController(
        AgentRuntime(
            config=RuntimeConfig(global_denied_actions=()),
            store=AgentStore(tmp_path / "agent.db"),
            planner=SequencePlanner(
                (
                    AgentProposal(
                        kind=ProposalKind.TOOL,
                        rationale="Inspect local evidence.",
                        call=ToolCall(
                            tool_id="agent.echo",
                            action="evidence.inspect",
                            operation="echo",
                            arguments={"value": "<script>alert(1)</script>"},
                        ),
                    ),
                    AgentProposal(
                        kind=ProposalKind.COMPLETE,
                        rationale="The bounded objective completed.",
                        final_summary="Completed safely.",
                    ),
                )
            ),
            tools=tools,
            evaluator=ResultEvaluator(),
            activity_service=AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity")),
        )
    )
    controller.create_task(
        task_id="task-activity",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-activity",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    controller.run("task-activity")

    snapshot = controller.runtime.activity_service.feed("task-activity")
    assert snapshot.events
    assert snapshot.run_state == "completed"
    assert {event.event_type for event in snapshot.events} >= {
        "run_created",
        "tool_execution_completed",
        "evaluation_completed",
        "run_completed",
    }
    objective_event = next(
        event for event in snapshot.events if event.event_type == "objective_received"
    )
    assert "objective" not in objective_event.metadata
    assert objective_event.metadata["objective_sha256"]
    assert objective_event.metadata["objective_summary"] == (
        "Bounded local objective recorded for governed execution."
    )


def test_controller_records_denied_policy_as_blocked(tmp_path) -> None:
    tools = ToolRegistry()
    tools.register(
        ToolSpec(
            tool_id="agent.echo",
            action="evidence.inspect",
            operation="echo",
            description="Echo approved local evidence.",
            risk=ToolRisk.READ_ONLY,
        ),
        lambda arguments, context: {"value": arguments["value"]},
    )
    controller = AgentController(
        AgentRuntime(
            config=RuntimeConfig(global_denied_actions=("evidence.inspect",)),
            store=AgentStore(tmp_path / "agent.db"),
            planner=SequencePlanner(
                (
                    AgentProposal(
                        kind=ProposalKind.TOOL,
                        rationale="Inspect local evidence.",
                        call=ToolCall(
                            tool_id="agent.echo",
                            action="evidence.inspect",
                            operation="echo",
                            arguments={"value": "blocked"},
                        ),
                    ),
                )
            ),
            tools=tools,
            evaluator=ResultEvaluator(),
            activity_service=AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity")),
        )
    )
    controller.create_task(
        task_id="task-denied",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-denied",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    controller.run("task-denied")
    snapshot = controller.runtime.activity_service.feed("task-denied")
    assert snapshot.run_state == "blocked"
    assert snapshot.terminal is True
    blocked_event = snapshot.events[-1]
    assert blocked_event.event_type == "run_blocked"
    assert blocked_event.policy_outcome == "denied"
    assert blocked_event.run_state == "blocked"


def test_controller_records_requires_approval_transition(tmp_path) -> None:
    tools = ToolRegistry()
    tools.register(
        ToolSpec(
            tool_id="agent.echo",
            action="evidence.inspect",
            operation="echo",
            description="Echo approved local evidence.",
            risk=ToolRisk.READ_ONLY,
        ),
        lambda arguments, context: {"value": arguments["value"]},
    )
    controller = AgentController(
        AgentRuntime(
            config=RuntimeConfig(global_denied_actions=()),
            store=AgentStore(tmp_path / "agent.db"),
            planner=SequencePlanner(
                (
                    AgentProposal(
                        kind=ProposalKind.TOOL,
                        rationale="Inspect local evidence.",
                        call=ToolCall(
                            tool_id="agent.echo",
                            action="evidence.inspect",
                            operation="echo",
                            arguments={"value": "approval"},
                        ),
                    ),
                )
            ),
            tools=tools,
            evaluator=ResultEvaluator(),
            activity_service=AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity")),
        )
    )
    controller.create_task(
        task_id="task-approval",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-approval",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            approval_required_actions=("evidence.inspect",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    controller.run("task-approval")
    snapshot = controller.runtime.activity_service.feed("task-approval")
    approval_event = next(
        event for event in snapshot.events if event.event_type == "approval_requested"
    )
    assert snapshot.run_state == "awaiting_approval"
    assert snapshot.terminal is False
    assert approval_event.policy_outcome == "requires_approval"
    assert approval_event.approval_requirement == "required"
    assert approval_event.approval_state == "pending"


def test_controller_records_blocked_state_for_repeated_failures(tmp_path) -> None:
    tools = ToolRegistry()

    def flaky_handler(arguments, context):
        raise ToolExecutionError("Retryable bounded failure.", retryable=True)

    tools.register(
        ToolSpec(
            tool_id="agent.flaky",
            action="evidence.inspect",
            operation="flaky",
            description="Return a retryable bounded failure.",
            risk=ToolRisk.READ_ONLY,
            retryable_errors=True,
        ),
        flaky_handler,
    )
    controller = AgentController(
        AgentRuntime(
            config=RuntimeConfig(global_denied_actions=()),
            store=AgentStore(tmp_path / "agent.db"),
            planner=SequencePlanner(
                (
                    AgentProposal(
                        kind=ProposalKind.TOOL,
                        rationale="Inspect local evidence.",
                        call=ToolCall(
                            tool_id="agent.flaky",
                            action="evidence.inspect",
                            operation="flaky",
                            arguments={},
                        ),
                    ),
                )
            ),
            tools=tools,
            evaluator=ResultEvaluator(),
            activity_service=AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity")),
        )
    )
    controller.create_task(
        task_id="task-blocked",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-blocked",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.flaky",),
            allowed_risks=(ToolRisk.READ_ONLY,),
            max_identical_failures=1,
        ),
    )
    controller.run("task-blocked")
    snapshot = controller.runtime.activity_service.feed("task-blocked")
    assert snapshot.run_state == "blocked"
    assert snapshot.terminal is True
    assert any(event.event_type == "run_blocked" for event in snapshot.events)


def test_controller_cancel_records_cancelled_transition(tmp_path) -> None:
    controller = _controller(tmp_path)
    controller.create_task(
        task_id="task-cancelled",
        objective="Perform a bounded local evidence task safely.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-cancelled",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    cancelled = controller.cancel("task-cancelled", "Operator stop for local test.")
    snapshot = controller.runtime.activity_service.feed("task-cancelled")
    assert cancelled.status.value == "cancelled"
    assert snapshot.run_state == "cancelled"
    assert snapshot.terminal is True
    assert snapshot.events[-1].event_type == "run_stopped"
    assert snapshot.events[-1].run_state == "cancelled"
