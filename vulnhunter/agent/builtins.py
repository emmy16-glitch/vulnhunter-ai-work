"""Safe local demonstration tools for the runtime foundation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vulnhunter.agent.models import ToolRisk, ToolSpec
from vulnhunter.agent.tools import ToolContext, ToolRegistry


def _echo(arguments: Mapping[str, Any], context: ToolContext) -> Mapping[str, Any]:
    return {
        "task_id": context.task.task_id,
        "value": arguments.get("value"),
    }


def build_safe_demo_tools() -> ToolRegistry:
    """Return a registry with no shell, network, connector, secret, or Git access."""

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            tool_id="agent.echo",
            action="evidence.inspect",
            operation="echo",
            description="Return supplied test evidence without external side effects.",
            risk=ToolRisk.READ_ONLY,
        ),
        _echo,
    )
    return registry
