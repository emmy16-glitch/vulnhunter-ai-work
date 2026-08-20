"""Authenticated workspace views for consent-verified public targets."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST
from pydantic import ValidationError

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.public_consent import (
    PublicConsentError,
    create_public_consent_authorization,
)
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import ScopeValidationError
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


def _timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PublicConsentError("Expiry must include a timezone offset.")
    return parsed.astimezone(UTC)


def _required(request: HttpRequest, key: str, *, maximum: int) -> str:
    value = request.POST.get(key, "").strip()
    if not value or len(value) > maximum:
        raise PublicConsentError(f"{key.replace('_', ' ').capitalize()} is required.")
    return value


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def verify_public_consent_view(request: HttpRequest) -> JsonResponse:
    """Verify public ownership consent for the authenticated scan workspace."""

    try:
        actor = authorized_actor(request.user, required_actions=("scan.create", "scan.read"))
        del actor
        target_url = _required(request, "target_url", maximum=2_000)
        challenge_token = _required(request, "challenge_token", maximum=256)
        owner = _required(request, "owner", maximum=200)
        approved_by = _required(request, "approved_by", maximum=200)
        purpose = _required(request, "purpose", maximum=2_000)
        expires_at = _timestamp(_required(request, "expires_at", maximum=64))
        store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))
        result = create_public_consent_authorization(
            target_url=target_url,
            challenge_token=challenge_token,
            owner=owner,
            approved_by=approved_by,
            purpose=purpose,
            expires_at=expires_at,
            limits=AuthorizationLimits(
                maximum_pages=100,
                maximum_depth=1,
                maximum_requests=500,
                minimum_request_delay_seconds=1.0,
            ),
            authorization_store=store,
        )
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    except (PublicConsentError, ScopeValidationError, ValidationError, ValueError) as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    return JsonResponse(
        {
            "authorization": {
                "id": result.record.authorization_id,
                "target_url": result.record.target_url,
                "expires_at": result.record.expires_at.isoformat(),
                "passive_only": result.passive_only,
                "consent_url": result.consent_url,
                "consent_sha256": result.consent_sha256,
            },
            "message": (
                "Public consent verified. The target is authorized for bounded "
                "passive mapping only."
            ),
        },
        status=201,
    )
