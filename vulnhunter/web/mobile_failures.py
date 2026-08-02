"""Typed, redacted failure records for mobile assessment operations."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

_ALLOWED_CATEGORIES = frozenset(
    {
        "approval_required",
        "dependency_unavailable",
        "input_invalid",
        "integrity_failure",
        "internal_failure",
        "policy_denied",
        "storage_failure",
        "tool_failure",
        "tool_missing",
        "tool_timeout",
        "worker_unavailable",
        "worker_lost",
    }
)


def _reference(*, category: str, stage: str, reason_code: str, operation_id: str | None) -> str:
    material = "|".join((category, stage, reason_code, operation_id or "unbound"))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    return f"vh-mobile-{digest}"


def mobile_failure(
    *,
    category: str,
    stage: str,
    reason_code: str,
    message: str,
    operation_id: str | None = None,
    user_action: str | None = None,
    operator_action: str | None = None,
    safe_retry: bool = False,
    retry_scope: str | None = None,
    preserved: Iterable[str] = (),
) -> dict[str, object]:
    """Build one bounded failure record without raw exception or secret material."""

    if category not in _ALLOWED_CATEGORIES:
        raise ValueError(f"Unsupported mobile failure category: {category}")
    if not stage.strip() or not reason_code.strip() or not message.strip():
        raise ValueError("Mobile failure stage, reason code and message are required")
    if safe_retry and not retry_scope:
        raise ValueError("A safe retry must declare its exact retry scope")
    if not safe_retry and retry_scope is not None:
        raise ValueError("A non-retryable failure cannot declare a retry scope")

    preserved_items = tuple(dict.fromkeys(item.strip() for item in preserved if item.strip()))
    return {
        "category": category,
        "stage": stage,
        "reason_code": reason_code,
        "reference": _reference(
            category=category,
            stage=stage,
            reason_code=reason_code,
            operation_id=operation_id,
        ),
        "message": message,
        "user_action": user_action,
        "operator_action": operator_action,
        "safe_retry": safe_retry,
        "retry_scope": retry_scope,
        "preserved": list(preserved_items),
    }


def execution_failure(
    *,
    state: str,
    failure: dict[str, object],
    job_id: str | None = None,
) -> dict[str, object]:
    """Return a worker execution envelope carrying one typed failure."""

    if state not in {"blocked", "failed", "gated", "rejected"}:
        raise ValueError("Typed failure execution state must be terminal or gated")
    message = str(failure.get("message") or "The mobile operation did not complete.")
    payload: dict[str, object] = {
        "state": state,
        "reason": message,
        "failure": failure,
    }
    if job_id:
        payload["job_id"] = job_id
    return payload


__all__ = ["execution_failure", "mobile_failure"]
