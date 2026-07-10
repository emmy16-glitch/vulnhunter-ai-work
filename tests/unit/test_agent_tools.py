from __future__ import annotations

import pytest

from vulnhunter.agent.models import AgentTask, PermissionManifest, ToolCall, ToolSpec
from vulnhunter.agent.tools import (
    ToolExecutionError,
    ToolRegistry,
    ToolRegistryError,
)


def task() -> AgentTask:
    return AgentTask(
        task_id="task-tools",
        objective="Exercise explicitly registered local tools.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-tools",
            role_id="orchestrator",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
        ),
    )


def spec(**overrides) -> ToolSpec:
    values = {
        "tool_id": "agent.echo",
        "action": "evidence.inspect",
        "operation": "echo",
        "description": "Echo approved local evidence.",
    }
    values.update(overrides)
    return ToolSpec(**values)


def call(**overrides) -> ToolCall:
    values = {
        "tool_id": "agent.echo",
        "action": "evidence.inspect",
        "operation": "echo",
        "arguments": {"value": "ok"},
    }
    values.update(overrides)
    return ToolCall(**values)


def test_register_and_execute_tool() -> None:
    registry = ToolRegistry()
    registry.register(spec(), lambda arguments, context: {"value": arguments["value"]})
    result = registry.execute(task(), call())
    assert result.success
    assert result.output == {"value": "ok"}


def test_duplicate_tool_is_rejected() -> None:
    registry = ToolRegistry()
    registry.register(spec(), lambda arguments, context: {})
    with pytest.raises(ToolRegistryError, match="already registered"):
        registry.register(spec(), lambda arguments, context: {})


def test_unknown_tool_is_rejected() -> None:
    with pytest.raises(ToolRegistryError, match="Unknown tool"):
        ToolRegistry().get("agent.missing")


def test_action_mismatch_is_rejected() -> None:
    registry = ToolRegistry()
    registry.register(spec(), lambda arguments, context: {})
    with pytest.raises(ToolRegistryError, match="action mismatch"):
        registry.execute(task(), call(action="scan.run"))


def test_operation_mismatch_is_rejected() -> None:
    registry = ToolRegistry()
    registry.register(spec(), lambda arguments, context: {})
    with pytest.raises(ToolRegistryError, match="operation mismatch"):
        registry.execute(task(), call(operation="other"))


def test_retryable_tool_error_is_normalized() -> None:
    registry = ToolRegistry()

    def handler(arguments, context):
        raise ToolExecutionError("temporary", retryable=True)

    registry.register(spec(), handler)
    result = registry.execute(task(), call())
    assert not result.success
    assert result.retryable
    assert result.error_message == "temporary"


def test_unexpected_exception_is_fail_closed() -> None:
    registry = ToolRegistry()

    def handler(arguments, context):
        raise RuntimeError("boom")

    registry.register(spec(), handler)
    result = registry.execute(task(), call())
    assert not result.success
    assert not result.retryable
    assert result.error_type == "RuntimeError"


def test_specs_are_sorted() -> None:
    registry = ToolRegistry()
    registry.register(spec(tool_id="z.tool"), lambda arguments, context: {})
    registry.register(spec(tool_id="a.tool"), lambda arguments, context: {})
    assert [item.tool_id for item in registry.specs()] == ["a.tool", "z.tool"]
