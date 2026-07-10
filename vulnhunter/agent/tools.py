"""Explicit tool registry for the bounded agent runtime."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from vulnhunter.agent.models import (
    AgentTask,
    ToolCall,
    ToolResult,
    ToolSpec,
    sha256_json,
)


class ToolRegistryError(ValueError):
    """Raised when tool declarations or calls violate registry invariants."""


class ToolExecutionError(RuntimeError):
    """Tool handler error with an explicit retry classification."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class ToolContext:
    """Minimal execution context intentionally excluding unrestricted services."""

    task: AgentTask


ToolHandler = Callable[[Mapping[str, Any], ToolContext], Mapping[str, Any]]


@dataclass(frozen=True)
class RegisteredTool:
    spec: ToolSpec
    handler: ToolHandler


class ToolRegistry:
    """In-memory registry that exposes only explicitly registered callables."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(self, spec: ToolSpec, handler: ToolHandler) -> None:
        if spec.tool_id in self._tools:
            raise ToolRegistryError(f"Tool is already registered: {spec.tool_id}")
        self._tools[spec.tool_id] = RegisteredTool(spec=spec, handler=handler)

    def get(self, tool_id: str) -> RegisteredTool:
        try:
            return self._tools[tool_id]
        except KeyError as exc:
            raise ToolRegistryError(f"Unknown tool: {tool_id}") from exc

    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(self._tools[key].spec for key in sorted(self._tools))

    def execute(self, task: AgentTask, call: ToolCall) -> ToolResult:
        registered = self.get(call.tool_id)
        spec = registered.spec
        if call.action != spec.action:
            raise ToolRegistryError(
                f"Tool action mismatch: expected {spec.action}, got {call.action}"
            )
        if call.operation != spec.operation:
            raise ToolRegistryError(
                f"Tool operation mismatch: expected {spec.operation}, got {call.operation}"
            )

        call_hash = call.fingerprint()
        try:
            output = dict(registered.handler(call.arguments, ToolContext(task=task)))
        except ToolExecutionError as exc:
            evidence = {
                "call_sha256": call_hash,
                "success": False,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "retryable": exc.retryable,
            }
            return ToolResult(
                success=False,
                error_type=type(exc).__name__,
                error_message=str(exc),
                retryable=exc.retryable,
                call_sha256=call_hash,
                evidence_sha256=sha256_json(evidence),
            )
        except Exception as exc:  # noqa: BLE001 - normalized into fail-closed evidence
            evidence = {
                "call_sha256": call_hash,
                "success": False,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "retryable": spec.retryable_errors,
            }
            return ToolResult(
                success=False,
                error_type=type(exc).__name__,
                error_message=str(exc),
                retryable=spec.retryable_errors,
                call_sha256=call_hash,
                evidence_sha256=sha256_json(evidence),
            )

        evidence = {
            "call_sha256": call_hash,
            "success": True,
            "output": output,
        }
        return ToolResult(
            success=True,
            output=output,
            call_sha256=call_hash,
            evidence_sha256=sha256_json(evidence),
        )
