"""Deterministic evaluation of tool results."""

from __future__ import annotations

from vulnhunter.agent.models import (
    EvaluationResult,
    EvaluationStatus,
    ToolCall,
    ToolResult,
    sha256_json,
)


class ResultEvaluator:
    """Classify normalized execution results without relying on model opinion."""

    def evaluate(self, call: ToolCall, result: ToolResult) -> EvaluationResult:
        if result.success:
            return EvaluationResult(
                status=EvaluationStatus.CONTINUE,
                reason="Tool execution succeeded.",
            )
        fingerprint = sha256_json(
            {
                "tool_id": call.tool_id,
                "action": call.action,
                "operation": call.operation,
                "error_type": result.error_type,
                "error_message": result.error_message,
            }
        )
        if result.retryable:
            return EvaluationResult(
                status=EvaluationStatus.RETRY,
                reason="Tool failure is explicitly retryable.",
                failure_fingerprint=fingerprint,
            )
        return EvaluationResult(
            status=EvaluationStatus.FAIL,
            reason="Tool failure is not retryable.",
            failure_fingerprint=fingerprint,
        )
