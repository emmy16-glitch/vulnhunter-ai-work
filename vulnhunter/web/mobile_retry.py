"""Idempotent, assessment-scoped retry execution for mobile analysis failures."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Protocol

from django.http import HttpRequest

from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.mobile_execution import enqueue_mobile_static_if_ready, mobile_static_status

_SESSION_MOBILE_RETRIES = "vulnhunter_conversation_mobile_retries"
_MAX_RETRY_RECEIPTS = 32
_SUPPORTED_SCOPES = frozenset({"worker_activation", "worker_status"})


class MobileRetryError(ValueError):
    """Raised when a retry request conflicts with authoritative assessment state."""


class _Session(Protocol):
    modified: bool

    def get(self, key: str, default: object = None) -> object: ...

    def __setitem__(self, key: str, value: object) -> None: ...


def _text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _retry_key(
    *,
    assessment_id: str,
    requested_by: str,
    scope: str,
    idempotency_key: str,
) -> str:
    material = f"{assessment_id}\x00{requested_by}\x00{scope}\x00{idempotency_key}".encode()
    return sha256(material).hexdigest()


def _load_ledger(request: HttpRequest) -> dict[str, dict[str, object]]:
    raw = request.session.get(_SESSION_MOBILE_RETRIES, {})
    if not isinstance(raw, dict):
        return {}
    return {
        str(key): deepcopy(value)
        for key, value in raw.items()
        if isinstance(key, str) and isinstance(value, dict)
    }


def _store_receipt(
    request: HttpRequest,
    *,
    key: str,
    receipt: dict[str, object],
) -> None:
    ledger = _load_ledger(request)
    ledger[key] = deepcopy(receipt)
    if len(ledger) > _MAX_RETRY_RECEIPTS:
        ledger = dict(list(ledger.items())[-_MAX_RETRY_RECEIPTS:])
    request.session[_SESSION_MOBILE_RETRIES] = ledger
    request.session.modified = True


def _failure_contract(plan: dict[str, object]) -> tuple[str, dict[str, object], dict[str, object]]:
    assessment_id = _text(plan.get("run_id"))
    execution = plan.get("execution")
    if assessment_id is None or not isinstance(execution, dict):
        raise MobileRetryError("A retry requires one selected persisted assessment execution.")
    failure = execution.get("failure")
    if not isinstance(failure, dict):
        raise MobileRetryError("The selected assessment has no persisted retryable failure.")
    if failure.get("safe_retry") is not True:
        raise MobileRetryError("The persisted failure does not permit a retry.")
    persisted_scope = _text(failure.get("retry_scope"))
    if persisted_scope not in _SUPPORTED_SCOPES:
        raise MobileRetryError("The persisted failure has no supported exact retry scope.")
    return assessment_id, execution, failure


def _attempt_history(execution: dict[str, object]) -> list[dict[str, object]]:
    raw = execution.get("retry_attempts")
    if not isinstance(raw, list):
        return []
    return [deepcopy(item) for item in raw if isinstance(item, dict)]


def retry_mobile_execution(
    request: HttpRequest,
    *,
    plan: dict[str, object],
    requested_by: str,
    retry_scope: str,
    idempotency_key: str,
    attachment: ConversationAttachment | None = None,
    artifact: MobileArtifactRecord | None = None,
) -> dict[str, object]:
    """Retry only the persisted failed scope and replay duplicate requests safely."""

    assessment_id, execution, failure = _failure_contract(plan)
    exact_scope = _text(retry_scope)
    persisted_scope = _text(failure.get("retry_scope"))
    reviewer_id = _text(requested_by)
    if reviewer_id is None:
        raise MobileRetryError("A retry requires one authenticated reviewer identity.")
    if exact_scope != persisted_scope:
        raise MobileRetryError("The requested retry scope does not match the persisted failure.")
    key_text = _text(idempotency_key)
    if key_text is None or len(key_text) > 200:
        raise MobileRetryError("A bounded idempotency key is required for retry execution.")

    ledger_key = _retry_key(
        assessment_id=assessment_id,
        requested_by=reviewer_id,
        scope=exact_scope,
        idempotency_key=key_text,
    )
    ledger = _load_ledger(request)
    replay = ledger.get(ledger_key)
    if replay is not None:
        return deepcopy(replay)

    previous_attempts = _attempt_history(execution)
    attempt_number = len(previous_attempts) + 1
    if exact_scope == "worker_status":
        job_id = _text(execution.get("job_id"))
        if job_id is None:
            raise MobileRetryError("A worker-status retry requires the preserved worker job.")
        retried = mobile_static_status(
            request,
            job_id=job_id,
            requested_by=reviewer_id,
        )
        if retried is None:
            raise MobileRetryError("The preserved worker job is unavailable to this session.")
    elif exact_scope == "worker_activation":
        attachment_id = _text(getattr(attachment, "artifact_id", None))
        artifact_id = _text(getattr(artifact, "artifact_id", None))
        if attachment_id is None or artifact_id is None or attachment_id != artifact_id:
            raise MobileRetryError(
                "A worker-activation retry requires the preserved verified artifact binding."
            )
        retried = enqueue_mobile_static_if_ready(
            request,
            plan=plan,
            attachment=attachment,
            artifact=artifact,
            requested_by=reviewer_id,
        )
    else:  # pragma: no cover
        raise MobileRetryError("The requested retry scope is not supported.")

    receipt = deepcopy(retried)
    receipt["retry_scope"] = exact_scope
    receipt["retry_attempt"] = attempt_number
    receipt["retry_replayed"] = False
    receipt["retry_attempts"] = [
        *previous_attempts,
        {
            "attempt": attempt_number,
            "scope": exact_scope,
            "state": _text(receipt.get("state")) or "unknown",
        },
    ]
    _store_receipt(request, key=ledger_key, receipt=receipt)
    return deepcopy(receipt)


__all__ = ["MobileRetryError", "retry_mobile_execution"]
