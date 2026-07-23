"""Explicit, short-lived authorization intake for pasted website targets."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from django.conf import settings

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import AuthorizationPolicyError, ScopeValidationError
from vulnhunter.scope import validate_target
from vulnhunter.scope.validator import Resolver, system_resolver
from vulnhunter.security import redact_text
from vulnhunter.web.assessment_workflow import (
    AssessmentWorkflowError,
    bind_nuclei_authorization,
    load_nuclei_authorization,
)


class ConversationalAuthorizationError(RuntimeError):
    """Raised when chat cannot safely create the requested authorization."""


@dataclass(frozen=True)
class PreparedConversationalAuthorization:
    authorization_id: str
    target: str
    port: int
    address_class: str
    reused: bool


def _stable_identifier(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.strip().casefold()).strip("-._")
    if len(normalized) < 2:
        normalized = "vh-user"
    return normalized[:128]


def _address_class(addresses: Iterable[str]) -> str:
    classes: set[str] = set()
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if address.is_loopback:
            raise ConversationalAuthorizationError(
                "Loopback targets cannot be handed to the isolated Nuclei worker."
            )
        if address.is_link_local or address.is_unspecified or address.is_multicast:
            raise ConversationalAuthorizationError(
                "Link-local, unspecified and multicast targets are not permitted."
            )
        if address.is_private:
            classes.add("private")
        elif address.is_global:
            classes.add("public")
        else:
            raise ConversationalAuthorizationError(
                "The target resolves to an unsupported special-use address."
            )
    if len(classes) != 1:
        raise ConversationalAuthorizationError(
            "The target mixes public and private addresses, so authorization fails closed."
        )
    return next(iter(classes))


def prepare_conversational_authorization(
    *,
    target_url: str,
    evidence_reference: str | None,
    identity_id: str,
    username: str,
    authorization_store: AuthorizationStore | None = None,
    resolver: Resolver = system_resolver,
    now: datetime | None = None,
) -> PreparedConversationalAuthorization:
    """Create or reuse an exact passive authorization for one pasted URL and port."""

    instant = (now or datetime.now(UTC)).astimezone(UTC)
    try:
        target = validate_target(target_url, resolver=resolver, allow_public=True)
    except (OSError, ScopeValidationError, ValueError) as exc:
        raise ConversationalAuthorizationError(str(exc)) from exc

    address_class = _address_class(target.resolved_addresses)
    evidence = redact_text(evidence_reference or "").strip()[:2_000]
    if address_class == "public" and len(evidence) < 8:
        raise ConversationalAuthorizationError(
            "This public website needs an authorization evidence reference. Send: "
            "Authorize this target. Evidence: <contract, ticket, or bug-bounty scope reference>."
        )
    if not evidence:
        evidence = "Interactive confirmation for a self-controlled private target."

    store = authorization_store or AuthorizationStore.from_path(
        Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE)
    )
    store.initialize()
    owner = identity_id.strip() or username.strip()
    record = next(
        (
            item
            for item in store.list(limit=250)
            if item.status == "active"
            and item.owner.casefold() in {identity_id.casefold(), username.casefold()}
            and item.target_url == target.normalized_url
            and instant < item.expires_at
        ),
        None,
    )
    reused = record is not None
    if record is None:
        try:
            record = issue_authorization(
                store,
                target,
                owner=owner,
                approved_by=f"{_stable_identifier(owner)}.interactive-confirmation",
                purpose="Governed passive website assessment requested in the chat workspace.",
                evidence_reference=evidence,
                expires_at=instant + timedelta(hours=12),
                limits=AuthorizationLimits(
                    maximum_pages=2,
                    maximum_depth=0,
                    maximum_requests=10,
                    minimum_request_delay_seconds=1,
                ),
                now=instant,
            )
        except (AuthorizationPolicyError, OSError, ValueError) as exc:
            raise ConversationalAuthorizationError(str(exc)) from exc

    principal = _stable_identifier(identity_id or username)
    try:
        _, engagement = load_nuclei_authorization(store, record.authorization_id)
        binding_ready = "passive" in engagement.approved_scan_profiles and (
            address_class != "private" or engagement.private_network_approved
        )
    except AssessmentWorkflowError:
        binding_ready = False
    if not binding_ready:
        try:
            bind_nuclei_authorization(
                store,
                authorization_id=record.authorization_id,
                approved_profiles=("passive",),
                private_network_approved=address_class == "private",
                recorded_by=principal,
                approval_basis=(
                    f"Interactive authorization for exact target {target.normalized_url}; "
                    f"evidence reference: {evidence}"
                ),
                now=instant,
            )
        except (AssessmentWorkflowError, OSError, ValueError) as exc:
            raise ConversationalAuthorizationError(str(exc)) from exc

    return PreparedConversationalAuthorization(
        authorization_id=record.authorization_id,
        target=target.normalized_url,
        port=target.port,
        address_class=address_class,
        reused=reused,
    )
