"""Consent-verified public-target authorization helpers.

This module deliberately supports only bounded passive HTTP mapping. It does not
activate the private-lab Nuclei worker or approve active scanning profiles.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlunsplit
from urllib.request import Request, urlopen

from vulnhunter.authorization.models import AuthorizationLimits, AuthorizationRecord
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import AuthorizationPolicyError, ScopeValidationError
from vulnhunter.scope import ApprovedTarget
from vulnhunter.scope.validator import Resolver, system_resolver
from vulnhunter.security import redact_text

_PUBLIC_CONSENT_PATH = "/.well-known/vulnhunter-consent.json"
_MAX_CHALLENGE_BYTES = 16_384
_MAX_AUTHORIZATION_LIFETIME = timedelta(days=30)

Fetcher = Callable[[str], tuple[int, bytes, str]]


class PublicConsentError(AuthorizationPolicyError):
    """Raised when public-target consent cannot be independently verified."""


@dataclass(frozen=True)
class PublicConsentAuthorization:
    """Result of creating a verified, passive-only public authorization."""

    record: AuthorizationRecord
    consent_url: str
    consent_sha256: str
    address_class: str = "public"
    passive_only: bool = True


def _default_fetcher(url: str) -> tuple[int, bytes, str]:
    request = Request(
        url,
        headers={
            "Accept": "application/json, text/plain;q=0.5",
            "User-Agent": "VulnHunter-public-consent-verifier/1.0",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=8) as response:  # noqa: S310 - URL is prevalidated below.
            body = response.read(_MAX_CHALLENGE_BYTES + 1)
            return int(response.status), body, str(response.headers.get("Content-Type", ""))
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise PublicConsentError(
            "The public consent challenge could not be fetched safely."
        ) from exc


def _public_addresses(addresses: Iterable[str]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise PublicConsentError("DNS returned an invalid address.") from exc
        if not address.is_global:
            raise PublicConsentError(
                "Public consent requires every resolved address to be globally routable."
            )
        normalized.add(str(address))
    if not normalized:
        raise PublicConsentError("The target did not resolve to a public address.")
    return tuple(sorted(normalized))


def _consent_url(target: ApprovedTarget) -> str:
    return urlunsplit((target.scheme, target.hostname, _PUBLIC_CONSENT_PATH, "", ""))


def _parse_challenge(body: bytes, *, token: str, content_type: str) -> None:
    if len(body) > _MAX_CHALLENGE_BYTES:
        raise PublicConsentError("The consent challenge response exceeded the bounded size limit.")
    text = body.decode("utf-8", errors="strict").strip()
    candidates: list[object] = []
    if "json" in content_type.lower() or text.startswith("{"):
        try:
            candidates.append(json.loads(text))
        except json.JSONDecodeError as exc:
            raise PublicConsentError("The consent challenge was not valid JSON.") from exc
    candidates.append(text)
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("token") == token:
            return
        if candidate == token:
            return
    raise PublicConsentError("The consent challenge token did not match.")


def create_public_consent_authorization(
    *,
    target_url: str,
    challenge_token: str,
    owner: str,
    approved_by: str,
    purpose: str,
    expires_at: datetime,
    limits: AuthorizationLimits,
    authorization_store: AuthorizationStore,
    resolver: Resolver = system_resolver,
    fetcher: Fetcher = _default_fetcher,
    now: datetime | None = None,
) -> PublicConsentAuthorization:
    """Verify a public domain challenge and issue a passive-only authorization.

    The challenge must be published by the target owner at the exact origin's
    ``/.well-known/vulnhunter-consent.json`` endpoint. The returned authorization
    is exact-origin/path-bound and is never bound to the private-only Nuclei worker.
    """

    token = redact_text(challenge_token).strip()
    if len(token) < 16 or len(token) > 256:
        raise PublicConsentError("The consent challenge token must be 16-256 characters.")
    if not token.isascii() or any(character.isspace() for character in token):
        raise PublicConsentError("The consent challenge token must be non-whitespace ASCII.")
    if not target_url.lower().startswith("https://"):
        raise PublicConsentError("Public consent requires an HTTPS target.")

    try:
        from vulnhunter.scope import validate_target

        target = validate_target(target_url, resolver=resolver, allow_public=True)
    except (OSError, ScopeValidationError, ValueError) as exc:
        raise PublicConsentError(str(exc)) from exc

    approved_addresses = _public_addresses(target.resolved_addresses)
    instant = (now or datetime.now(UTC)).astimezone(UTC)
    end = expires_at.astimezone(UTC)
    if end <= instant or end - instant > _MAX_AUTHORIZATION_LIFETIME:
        raise PublicConsentError("Public consent authorization must expire within 30 days.")

    consent_url = _consent_url(target)
    status, body, content_type = fetcher(consent_url)
    if status != 200:
        raise PublicConsentError("The public consent challenge endpoint did not return HTTP 200.")
    _parse_challenge(body, token=token, content_type=content_type)
    consent_sha256 = hashlib.sha256(body).hexdigest()

    authorization_store.initialize()
    record = issue_authorization(
        authorization_store,
        target.model_copy(update={"resolved_addresses": approved_addresses}),
        owner=owner,
        approved_by=approved_by,
        purpose=purpose,
        expires_at=end,
        limits=limits,
        evidence_reference=f"{consent_url}#sha256={consent_sha256}",
        now=instant,
    )
    authorization_store.append_event(
        record.authorization_id,
        "public_consent_verified",
        {
            "consent_url": consent_url,
            "consent_sha256": consent_sha256,
            "resolved_addresses": list(approved_addresses),
            "target_url": record.target_url,
            "passive_only": True,
            "verified_at": instant.isoformat(),
        },
    )
    return PublicConsentAuthorization(
        record=record,
        consent_url=consent_url,
        consent_sha256=consent_sha256,
    )


def has_verified_public_consent(
    store: AuthorizationStore,
    authorization_id: str,
) -> bool:
    """Return true only when an authorization has a valid consent audit event."""

    record = store.get(authorization_id)
    if not record.evidence_reference or not record.target_url.startswith("https://"):
        return False
    return any(
        event.event_type == "public_consent_verified"
        for event in store.list_events(authorization_id)
    )
