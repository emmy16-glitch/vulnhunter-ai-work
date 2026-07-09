"""Business rules for issuing and validating explicit scan authorization."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.authorization.models import (
    AuthorizationDecision,
    AuthorizationLimits,
    AuthorizationRecord,
    authorization_record_sha256,
)
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import AuthorizationPolicyError
from vulnhunter.scope import ApprovedTarget
from vulnhunter.security import redact_text, redact_url

_MAX_AUTHORIZATION_LIFETIME = timedelta(days=365)


def _safe_required(value: str, *, field_name: str, maximum: int) -> str:
    result = redact_text(value).strip()[:maximum]
    if not result:
        raise AuthorizationPolicyError(f"{field_name} is required.")
    return result


def _normalise_time(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AuthorizationPolicyError(f"{field_name} must include a timezone.")
    return value.astimezone(UTC)


def _path_is_within(boundary: str, candidate: str) -> bool:
    if boundary == "/":
        return True
    root = boundary.rstrip("/")
    current = candidate.rstrip("/") or "/"
    return current == root or current.startswith(root + "/")


def issue_authorization(
    store: AuthorizationStore,
    target: ApprovedTarget,
    *,
    owner: str,
    approved_by: str,
    purpose: str,
    expires_at: datetime,
    limits: AuthorizationLimits,
    valid_from: datetime | None = None,
    evidence_reference: str | None = None,
    now: datetime | None = None,
) -> AuthorizationRecord:
    """Create a bounded authorization record after scope validation."""
    issued_at = _normalise_time(now or datetime.now(UTC), field_name="issued_at")
    starts_at = _normalise_time(valid_from or issued_at, field_name="valid_from")
    ends_at = _normalise_time(expires_at, field_name="expires_at")

    if starts_at < issued_at - timedelta(minutes=5):
        raise AuthorizationPolicyError("valid_from cannot substantially predate record issuance.")
    if ends_at <= starts_at:
        raise AuthorizationPolicyError("expires_at must be later than valid_from.")
    if ends_at - starts_at > _MAX_AUTHORIZATION_LIFETIME:
        raise AuthorizationPolicyError("Authorization lifetime cannot exceed 365 days.")

    record_data: dict[str, object] = {
        "authorization_id": f"auth-{uuid4().hex[:20]}",
        "target_url": redact_url(target.normalized_url),
        "scheme": target.scheme,
        "hostname": target.hostname,
        "port": target.port,
        "path_boundary": target.path,
        "approved_addresses": tuple(target.resolved_addresses),
        "owner": _safe_required(owner, field_name="owner", maximum=300),
        "approved_by": _safe_required(
            approved_by,
            field_name="approved_by",
            maximum=300,
        ),
        "purpose": _safe_required(purpose, field_name="purpose", maximum=2_000),
        "evidence_reference": (
            redact_text(evidence_reference).strip()[:2_000] if evidence_reference else None
        ),
        "issued_at": issued_at,
        "valid_from": starts_at,
        "expires_at": ends_at,
        "limits": limits,
        "status": "active",
        "revoked_at": None,
        "revocation_reason": None,
        "record_sha256": "0" * 64,
    }
    record_data["record_sha256"] = authorization_record_sha256(record_data)
    record = AuthorizationRecord.model_validate(record_data)
    return store.create(record)


def validate_scan_authorization(
    store: AuthorizationStore,
    authorization_id: str,
    target: ApprovedTarget,
    *,
    maximum_pages: int,
    maximum_depth: int,
    maximum_requests: int,
    request_delay_seconds: float,
    now: datetime | None = None,
    record_event: bool = True,
) -> AuthorizationDecision:
    """Validate permission, target containment, time, and requested limits."""
    checked_at = _normalise_time(now or datetime.now(UTC), field_name="checked_at")
    record = store.get(authorization_id)

    def reject(message: str) -> AuthorizationPolicyError:
        if record_event:
            store.append_event(
                authorization_id,
                "validation_rejected",
                {"reason": message, "target_url": target.normalized_url},
            )
        return AuthorizationPolicyError(message)

    if record.status != "active":
        raise reject(f"Authorization {authorization_id} is revoked.")
    if checked_at < record.valid_from:
        raise reject(f"Authorization {authorization_id} is not active yet.")
    if checked_at >= record.expires_at:
        raise reject(f"Authorization {authorization_id} has expired.")

    if (
        target.scheme != record.scheme
        or target.hostname != record.hostname
        or target.port != record.port
    ):
        raise reject("Requested target does not match the authorized origin.")
    if not _path_is_within(record.path_boundary, target.path):
        raise reject("Requested target leaves the authorized path boundary.")

    current_addresses = set(target.resolved_addresses)
    approved_addresses = set(record.approved_addresses)
    if not current_addresses or not current_addresses.issubset(approved_addresses):
        raise reject("Current target addresses exceed the authorization snapshot.")

    requested = AuthorizationLimits(
        maximum_pages=maximum_pages,
        maximum_depth=maximum_depth,
        maximum_requests=maximum_requests,
        minimum_request_delay_seconds=request_delay_seconds,
    )
    if requested.maximum_pages > record.limits.maximum_pages:
        raise reject("Requested page limit exceeds the authorization ceiling.")
    if requested.maximum_depth > record.limits.maximum_depth:
        raise reject("Requested depth exceeds the authorization ceiling.")
    if requested.maximum_requests > record.limits.maximum_requests:
        raise reject("Requested request budget exceeds the authorization ceiling.")
    if requested.minimum_request_delay_seconds < record.limits.minimum_request_delay_seconds:
        raise reject("Requested delay is faster than the authorization permits.")

    if record_event:
        store.append_event(
            authorization_id,
            "validated",
            {
                "target_url": target.normalized_url,
                "maximum_pages": maximum_pages,
                "maximum_depth": maximum_depth,
                "maximum_requests": maximum_requests,
                "request_delay_seconds": request_delay_seconds,
            },
        )

    return AuthorizationDecision(
        authorization_id=authorization_id,
        target_url=target.normalized_url,
        checked_at=checked_at,
        limits=requested,
    )
