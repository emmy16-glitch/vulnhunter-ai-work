"""Planner contracts for deterministic scripts and structured model gateways."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from pydantic import ValidationError

from vulnhunter.agent.models import AgentProposal, AgentTask, AuditEvent, ToolSpec


class PlannerError(ValueError):
    """Raised when a planner cannot provide a valid structured proposal."""


class Planner(Protocol):
    """Minimal planner interface used by the controller."""

    def propose(
        self,
        task: AgentTask,
        events: Sequence[AuditEvent],
        tools: Sequence[ToolSpec],
    ) -> AgentProposal: ...


class SequencePlanner:
    """Deterministic planner useful for tests, dry runs, and approved playbooks."""

    def __init__(self, proposals: Sequence[AgentProposal]) -> None:
        if not proposals:
            raise PlannerError("SequencePlanner requires at least one proposal")
        self._proposals = tuple(proposals)

    def propose(
        self,
        task: AgentTask,
        events: Sequence[AuditEvent],
        tools: Sequence[ToolSpec],
    ) -> AgentProposal:
        del events, tools
        index = int(task.memory.get("planner_cursor", 0))
        if index >= len(self._proposals):
            raise PlannerError("SequencePlanner has no remaining proposal")
        return self._proposals[index]


class ModelGateway(Protocol):
    """Gateway contract; implementations may call a local or remote model later."""

    def complete(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class CallableModelGateway:
    """Adapter for a supplied structured-response callable."""

    def __init__(self, callback: Callable[[Mapping[str, Any]], Mapping[str, Any]]) -> None:
        self._callback = callback

    def complete(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._callback(request)


class ModelPlanner:
    """Convert strict model output into a validated proposal without executing it."""

    def __init__(self, gateway: ModelGateway) -> None:
        self.gateway = gateway

    def propose(
        self,
        task: AgentTask,
        events: Sequence[AuditEvent],
        tools: Sequence[ToolSpec],
    ) -> AgentProposal:
        request = {
            "objective": task.objective,
            "task": task.model_dump(mode="json"),
            "recent_events": [event.model_dump(mode="json") for event in tuple(events)[-10:]],
            "available_tools": [tool.model_dump(mode="json") for tool in tools],
            "rules": {
                "structured_output_only": True,
                "no_direct_tool_execution": True,
                "respect_permission_manifest": True,
            },
        }
        try:
            response = dict(self.gateway.complete(request))
            return AgentProposal.model_validate(response)
        except (TypeError, ValueError, ValidationError) as exc:
            raise PlannerError(f"Model gateway returned an invalid proposal: {exc}") from exc
