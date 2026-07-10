"""Governed campaign lifecycle, identity enforcement, and dataset release gates."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from vulnhunter.authorization import AuthorizationStore
from vulnhunter.exceptions import (
    AuthorizationError,
    GovernanceAuthenticationError,
    GovernancePolicyError,
    GovernanceStateError,
)
from vulnhunter.governance.auth import hash_secret, verify_secret
from vulnhunter.governance.models import (
    CampaignApplication,
    CampaignLimits,
    CampaignRecord,
    CampaignScan,
    DatasetReleaseManifest,
    IdentityRole,
    IdentityStatus,
    ReleaseAssessment,
    ReviewAssignment,
    ReviewAttestation,
    ReviewerIdentity,
    ReviewOutcome,
    application_record_sha256,
    assignment_record_sha256,
    attestation_record_sha256,
    campaign_manifest_sha256,
    campaign_record_sha256,
    campaign_scan_record_sha256,
    canonical_sha256,
    identity_record_sha256,
    release_manifest_sha256,
)
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.review import normalize_reviewer_id
from vulnhunter.security import redact_text, redact_url

_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise GovernancePolicyError("Governance timestamps must include a timezone.")
    return current.astimezone(UTC)


def _safe_text(value: str, *, field_name: str, maximum: int) -> str:
    result = redact_text(value).strip()[:maximum]
    if not result:
        raise GovernancePolicyError(f"{field_name} is required.")
    return result


def _normalize_tags(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    normalized = tuple(sorted({item.strip().lower() for item in values if item.strip()}))
    invalid = [item for item in normalized if not _TAG_PATTERN.fullmatch(item)]
    if invalid:
        raise GovernancePolicyError(
            "Conflict tags must contain lowercase letters, digits, dots, underscores, or hyphens."
        )
    return normalized


def _normalize_roles(values: tuple[str, ...] | list[str]) -> tuple[IdentityRole, ...]:
    allowed = {"campaign_admin", "reviewer", "adjudicator"}
    normalized = tuple(sorted(set(values)))
    if not normalized or any(item not in allowed for item in normalized):
        raise GovernancePolicyError(
            "At least one valid role is required: campaign_admin, reviewer, adjudicator."
        )
    return normalized  # type: ignore[return-value]


def authenticate_identity(
    store: GovernanceStore,
    reviewer_id: str,
    secret: str,
    *,
    required_role: IdentityRole | None = None,
) -> ReviewerIdentity:
    """Authenticate one active identity and optionally enforce a role."""
    normalized = normalize_reviewer_id(reviewer_id)
    identity = store.get_identity(normalized)
    if identity.status != "active":
        raise GovernanceAuthenticationError(
            f"Identity {normalized} is {identity.status} and cannot authenticate."
        )
    if not verify_secret(
        secret,
        encoded_salt=identity.credential_salt,
        encoded_hash=identity.credential_hash,
    ):
        raise GovernanceAuthenticationError("Reviewer authentication failed.")
    if required_role is not None and required_role not in identity.roles:
        raise GovernancePolicyError(
            f"Identity {normalized} does not hold the {required_role} role."
        )
    return identity


def bootstrap_administrator(
    store: GovernanceStore,
    *,
    reviewer_id: str,
    display_name: str,
    secret: str,
    now: datetime | None = None,
) -> ReviewerIdentity:
    """Create the only unauthenticated account: the first local administrator."""
    if store.identity_count() != 0:
        raise GovernancePolicyError(
            "Bootstrap is permitted only when the governance registry is empty."
        )
    normalized = normalize_reviewer_id(reviewer_id)
    salt, credential_hash = hash_secret(secret)
    data: dict[str, object] = {
        "reviewer_id": normalized,
        "display_name": _safe_text(
            display_name,
            field_name="display_name",
            maximum=200,
        ),
        "roles": ("campaign_admin",),
        "conflict_tags": (),
        "status": "active",
        "credential_salt": salt,
        "credential_hash": credential_hash,
        "created_by": normalized,
        "created_at": _now(now),
        "status_changed_at": None,
        "status_reason": None,
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = identity_record_sha256(data)
    return store.create_identity(ReviewerIdentity.model_validate(data))


def create_identity(
    store: GovernanceStore,
    *,
    actor_id: str,
    actor_secret: str,
    reviewer_id: str,
    display_name: str,
    secret: str,
    roles: tuple[str, ...],
    conflict_tags: tuple[str, ...] = (),
    now: datetime | None = None,
) -> ReviewerIdentity:
    """Create a local identity after authenticating a campaign administrator."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    normalized = normalize_reviewer_id(reviewer_id)
    if normalized == actor.reviewer_id:
        raise GovernancePolicyError("Administrators cannot recreate their own identity.")
    salt, credential_hash = hash_secret(secret)
    data: dict[str, object] = {
        "reviewer_id": normalized,
        "display_name": _safe_text(
            display_name,
            field_name="display_name",
            maximum=200,
        ),
        "roles": _normalize_roles(roles),
        "conflict_tags": _normalize_tags(conflict_tags),
        "status": "active",
        "credential_salt": salt,
        "credential_hash": credential_hash,
        "created_by": actor.reviewer_id,
        "created_at": _now(now),
        "status_changed_at": None,
        "status_reason": None,
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = identity_record_sha256(data)
    return store.create_identity(ReviewerIdentity.model_validate(data))


def change_identity_status(
    store: GovernanceStore,
    *,
    actor_id: str,
    actor_secret: str,
    reviewer_id: str,
    status: IdentityStatus,
    reason: str,
    now: datetime | None = None,
) -> ReviewerIdentity:
    """Disable or permanently revoke another identity."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    normalized = normalize_reviewer_id(reviewer_id)
    if normalized == actor.reviewer_id:
        raise GovernancePolicyError("Administrators cannot change their own status.")
    if status not in {"disabled", "revoked"}:
        raise GovernancePolicyError("Status changes support only disabled or revoked.")
    current = store.get_identity(normalized)
    if current.status == "revoked":
        raise GovernanceStateError("A revoked identity cannot be changed.")
    if current.status == status:
        raise GovernanceStateError(f"Identity {normalized} is already {status}.")
    data = current.model_dump()
    data.update(
        {
            "status": status,
            "status_changed_at": _now(now),
            "status_reason": _safe_text(reason, field_name="reason", maximum=2_000),
            "record_sha256": "0" * 64,
        }
    )
    data["record_sha256"] = identity_record_sha256(data)
    replacement = ReviewerIdentity.model_validate(data)
    return store.replace_identity(
        replacement,
        actor_id=actor.reviewer_id,
        event_type=status,
        detail={"reason": replacement.status_reason},
    )


def reactivate_identity(
    store: GovernanceStore,
    *,
    actor_id: str,
    actor_secret: str,
    reviewer_id: str,
    reason: str,
    now: datetime | None = None,
) -> ReviewerIdentity:
    """Reactivate a disabled identity; revoked identities remain permanent."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    normalized = normalize_reviewer_id(reviewer_id)
    if normalized == actor.reviewer_id:
        raise GovernancePolicyError("Administrators cannot change their own status.")
    current = store.get_identity(normalized)
    if current.status == "revoked":
        raise GovernanceStateError("A revoked identity cannot be reactivated.")
    if current.status != "disabled":
        raise GovernanceStateError("Only disabled identities can be reactivated.")
    data = current.model_dump()
    data.update(
        {
            "status": "active",
            "status_changed_at": _now(now),
            "status_reason": _safe_text(reason, field_name="reason", maximum=2_000),
            "record_sha256": "0" * 64,
        }
    )
    data["record_sha256"] = identity_record_sha256(data)
    replacement = ReviewerIdentity.model_validate(data)
    return store.replace_identity(
        replacement,
        actor_id=actor.reviewer_id,
        event_type="reactivated",
        detail={"reason": replacement.status_reason},
    )


def create_campaign(
    store: GovernanceStore,
    *,
    actor_id: str,
    actor_secret: str,
    title: str,
    purpose: str,
    owner_id: str,
    limits: CampaignLimits,
    minimum_applications: int = 2,
    minimum_application_families: int = 2,
    minimum_reviewed_observations: int = 20,
    now: datetime | None = None,
) -> CampaignRecord:
    """Create a draft campaign that cannot collect until independently approved."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    owner = normalize_reviewer_id(owner_id)
    store.get_identity(owner)
    data: dict[str, object] = {
        "campaign_id": f"campaign-{uuid4().hex[:20]}",
        "title": _safe_text(title, field_name="title", maximum=300),
        "purpose": _safe_text(purpose, field_name="purpose", maximum=2_000),
        "owner_id": owner,
        "created_by": actor.reviewer_id,
        "created_at": _now(now),
        "limits": limits,
        "minimum_applications": minimum_applications,
        "minimum_application_families": minimum_application_families,
        "minimum_reviewed_observations": minimum_reviewed_observations,
        "status": "draft",
        "approved_by": None,
        "approved_at": None,
        "approved_manifest_sha256": None,
        "completed_at": None,
        "cancelled_at": None,
        "cancellation_reason": None,
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = campaign_record_sha256(data)
    return store.create_campaign(CampaignRecord.model_validate(data))


def _authorization_is_current(record, *, now: datetime) -> None:
    if record.status != "active":
        raise GovernancePolicyError(f"Authorization {record.authorization_id} is revoked.")
    if now < record.valid_from:
        raise GovernancePolicyError(f"Authorization {record.authorization_id} is not active yet.")
    if now >= record.expires_at:
        raise GovernancePolicyError(f"Authorization {record.authorization_id} has expired.")


def _limits_within_authorization(limits: CampaignLimits, authorization) -> None:
    if limits.maximum_pages > authorization.limits.maximum_pages:
        raise GovernancePolicyError("Campaign page limit exceeds authorization.")
    if limits.maximum_depth > authorization.limits.maximum_depth:
        raise GovernancePolicyError("Campaign depth exceeds authorization.")
    if limits.maximum_requests > authorization.limits.maximum_requests:
        raise GovernancePolicyError("Campaign request limit exceeds authorization.")
    if limits.minimum_request_delay_seconds < authorization.limits.minimum_request_delay_seconds:
        raise GovernancePolicyError("Campaign delay is faster than authorization.")


def register_application(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    authorization_id: str,
    application_family: str,
    environment: str,
    conflict_tags: tuple[str, ...] = (),
    now: datetime | None = None,
) -> CampaignApplication:
    """Bind one exact authorization record into a campaign draft."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    campaign = store.get_campaign(campaign_id)
    if campaign.status != "draft":
        raise GovernanceStateError("Applications can be added only to draft campaigns.")
    if actor.reviewer_id != campaign.created_by:
        raise GovernancePolicyError("Only the authenticated campaign creator may edit the draft.")
    current_time = _now(now)
    authorization = authorization_store.get(authorization_id)
    _authorization_is_current(authorization, now=current_time)
    _limits_within_authorization(campaign.limits, authorization)
    data: dict[str, object] = {
        "application_id": f"app-{uuid4().hex[:20]}",
        "campaign_id": campaign.campaign_id,
        "application_family": _safe_text(
            application_family,
            field_name="application_family",
            maximum=200,
        ).lower(),
        "environment": _safe_text(
            environment,
            field_name="environment",
            maximum=200,
        ).lower(),
        "target_url": redact_url(authorization.target_url),
        "authorization_id": authorization.authorization_id,
        "authorization_record_sha256": authorization.record_sha256,
        "conflict_tags": _normalize_tags(conflict_tags),
        "registered_by": actor.reviewer_id,
        "registered_at": current_time,
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = application_record_sha256(data)
    return store.create_application(CampaignApplication.model_validate(data))


def _validate_campaign_applications(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    campaign: CampaignRecord,
    *,
    now: datetime,
) -> tuple[CampaignApplication, ...]:
    applications = store.list_applications(campaign.campaign_id)
    if len(applications) < campaign.minimum_applications:
        raise GovernancePolicyError("Campaign does not meet its minimum application requirement.")
    families = {item.application_family for item in applications}
    if len(families) < campaign.minimum_application_families:
        raise GovernancePolicyError(
            "Campaign does not meet its application-family diversity requirement."
        )
    for application in applications:
        authorization = authorization_store.get(application.authorization_id)
        _authorization_is_current(authorization, now=now)
        _limits_within_authorization(campaign.limits, authorization)
        if authorization.record_sha256 != application.authorization_record_sha256:
            raise GovernancePolicyError(
                f"Authorization {authorization.authorization_id} changed after registration."
            )
        if redact_url(authorization.target_url) != application.target_url:
            raise GovernancePolicyError("Application target no longer matches authorization.")
    return applications


def approve_campaign(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    now: datetime | None = None,
) -> CampaignRecord:
    """Approve the exact immutable draft manifest using a distinct administrator."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    campaign = store.get_campaign(campaign_id)
    if campaign.status != "draft":
        raise GovernanceStateError("Only draft campaigns can be approved.")
    if actor.reviewer_id == campaign.created_by:
        raise GovernancePolicyError("Campaign creators cannot approve their own draft.")
    current_time = _now(now)
    applications = _validate_campaign_applications(
        store,
        authorization_store,
        campaign,
        now=current_time,
    )
    manifest_sha = campaign_manifest_sha256(campaign, applications)
    data = campaign.model_dump()
    data.update(
        {
            "status": "approved",
            "approved_by": actor.reviewer_id,
            "approved_at": current_time,
            "approved_manifest_sha256": manifest_sha,
            "record_sha256": "0" * 64,
        }
    )
    data["record_sha256"] = campaign_record_sha256(data)
    replacement = CampaignRecord.model_validate(data)
    return store.replace_campaign(
        replacement,
        actor_id=actor.reviewer_id,
        event_type="approved",
        detail={"manifest_sha256": manifest_sha},
    )


def activate_campaign(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    now: datetime | None = None,
) -> CampaignRecord:
    """Activate an approved campaign after revalidating the frozen manifest."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    campaign = store.get_campaign(campaign_id)
    if campaign.status != "approved":
        raise GovernanceStateError("Only approved campaigns can be activated.")
    applications = _validate_campaign_applications(
        store,
        authorization_store,
        campaign,
        now=_now(now),
    )
    current_manifest = campaign_manifest_sha256(campaign, applications)
    if current_manifest != campaign.approved_manifest_sha256:
        raise GovernancePolicyError("The approved campaign manifest changed.")
    data = campaign.model_dump()
    data.update({"status": "active", "record_sha256": "0" * 64})
    data["record_sha256"] = campaign_record_sha256(data)
    replacement = CampaignRecord.model_validate(data)
    return store.replace_campaign(
        replacement,
        actor_id=actor.reviewer_id,
        event_type="activated",
        detail={"manifest_sha256": current_manifest},
    )


def scan_snapshot_sha256(scan) -> str:
    """Hash the persisted scan summary used for campaign provenance checks."""
    return canonical_sha256(scan.model_dump(mode="json"), exclude=set())


def _matching_authorization_events(
    authorization_store: AuthorizationStore,
    *,
    authorization_id: str,
    scan_id: int,
    scan_database: Path,
    campaign: CampaignRecord,
    target_url: str,
    scan_snapshot_sha256: str,
) -> tuple[int, int, int]:
    events = tuple(reversed(authorization_store.list_events(authorization_id, limit=2_000)))
    resolved_database = str(scan_database.expanduser().resolve())
    starts = [
        event
        for event in events
        if event.event_type == "scan_started"
        and int(event.detail.get("scan_id", -1)) == scan_id
        and str(event.detail.get("scan_database", "")) == resolved_database
    ]
    if len(starts) != 1:
        raise GovernancePolicyError(
            "The authorization log does not contain exactly one matching scan_started event."
        )
    started = starts[0]
    completed: list[object] = []
    for event in events:
        if event.event_type != "scan_completed":
            continue
        detail = event.detail
        try:
            event_scan_id = int(detail["scan_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GovernancePolicyError(
                "The authorization log contains malformed scan_completed metadata."
            ) from exc
        if event_scan_id != scan_id:
            continue
        if event.event_id <= started.event_id:
            continue
        if event.authorization_id != authorization_id:
            raise GovernancePolicyError(
                "The authorization log scan_completed event belongs to a different authorization."
            )
        required_detail = {
            "scan_database": resolved_database,
            "target_url": target_url,
            "scan_snapshot_sha256": scan_snapshot_sha256,
        }
        missing = [key for key in required_detail if key not in detail]
        if missing:
            raise GovernancePolicyError(
                "The authorization log contains incomplete scan_completed metadata."
            )
        mismatched = [
            key for key, value in required_detail.items() if str(detail.get(key, "")) != value
        ]
        if mismatched:
            raise GovernancePolicyError(
                "The authorization log scan_completed metadata does not match the linked scan."
            )
        completed.append(event)
    if len(completed) != 1:
        raise GovernancePolicyError(
            "The authorization log does not contain exactly one matching scan_completed event."
        )
    validations = [
        event
        for event in events
        if event.event_type == "validated"
        and event.event_id < started.event_id
        and str(event.detail.get("target_url", "")) == target_url
    ]
    if not validations:
        raise GovernancePolicyError(
            "The scan has no preceding successful authorization validation event."
        )
    validation = validations[-1]
    if int(validation.detail.get("maximum_pages", -1)) > campaign.limits.maximum_pages:
        raise GovernancePolicyError("The scan page limit exceeded the campaign ceiling.")
    if int(validation.detail.get("maximum_depth", -1)) > campaign.limits.maximum_depth:
        raise GovernancePolicyError("The scan depth exceeded the campaign ceiling.")
    if int(validation.detail.get("maximum_requests", -1)) > campaign.limits.maximum_requests:
        raise GovernancePolicyError("The scan request budget exceeded the campaign ceiling.")
    delay = float(validation.detail.get("request_delay_seconds", -1))
    if delay < campaign.limits.minimum_request_delay_seconds:
        raise GovernancePolicyError("The scan delay was faster than the campaign permits.")
    return validation.event_id, started.event_id, completed[0].event_id


def link_scan(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    repository: ScanRepository,
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    application_id: str,
    scan_database: Path,
    scan_id: int,
    now: datetime | None = None,
) -> CampaignScan:
    """Link a completed authorized scan after cross-database evidence validation."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    campaign = store.get_campaign(campaign_id)
    if campaign.status != "active":
        raise GovernanceStateError("Scans can be linked only to active campaigns.")
    application = store.get_application(application_id)
    if application.campaign_id != campaign.campaign_id:
        raise GovernancePolicyError("Application does not belong to this campaign.")
    authorization = authorization_store.get(application.authorization_id)
    current_time = _now(now)
    _authorization_is_current(authorization, now=current_time)
    if authorization.record_sha256 != application.authorization_record_sha256:
        raise GovernancePolicyError("Application authorization changed after approval.")
    existing_scans = [
        item
        for item in store.list_scans(campaign_id)
        if item.application_id == application.application_id
    ]
    if len(existing_scans) >= campaign.limits.maximum_scans_per_application:
        raise GovernancePolicyError("Application reached the campaign scan ceiling.")
    scan = repository.get_scan(scan_id)
    if scan.status != "completed":
        raise GovernancePolicyError("Only completed scans can enter a campaign.")
    if scan.target_url != application.target_url:
        raise GovernancePolicyError("Scan target does not match campaign application.")
    if scan.pages_visited > campaign.limits.maximum_pages:
        raise GovernancePolicyError("Completed scan exceeded the campaign page ceiling.")
    scan_snapshot = scan_snapshot_sha256(scan)
    validation_id, started_id, completed_id = _matching_authorization_events(
        authorization_store,
        authorization_id=application.authorization_id,
        scan_id=scan_id,
        scan_database=scan_database,
        campaign=campaign,
        target_url=application.target_url,
        scan_snapshot_sha256=scan_snapshot,
    )
    data: dict[str, object] = {
        "campaign_id": campaign.campaign_id,
        "application_id": application.application_id,
        "scan_database": str(scan_database.expanduser().resolve()),
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "pages_visited": scan.pages_visited,
        "observations_count": scan.observations_count,
        "validation_event_id": validation_id,
        "scan_started_event_id": started_id,
        "scan_completed_event_id": completed_id,
        "scan_snapshot_sha256": scan_snapshot,
        "linked_by": actor.reviewer_id,
        "linked_at": current_time,
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = campaign_scan_record_sha256(data)
    return store.create_scan(CampaignScan.model_validate(data))


def _require_assignment_identity(
    store: GovernanceStore,
    reviewer_id: str,
    *,
    role: IdentityRole,
    application: CampaignApplication,
    campaign: CampaignRecord,
) -> ReviewerIdentity:
    normalized = normalize_reviewer_id(reviewer_id)
    identity = store.get_identity(normalized)
    if identity.status != "active":
        raise GovernancePolicyError(f"Identity {normalized} is not active.")
    if role not in identity.roles:
        raise GovernancePolicyError(f"Identity {normalized} lacks the {role} role.")
    if normalized in {campaign.created_by, campaign.owner_id}:
        raise GovernancePolicyError(
            "Campaign creators and owners cannot review their own campaign data."
        )
    conflicts = set(identity.conflict_tags).intersection(application.conflict_tags)
    if conflicts:
        raise GovernancePolicyError(f"Identity {normalized} has a declared application conflict.")
    return identity


def assign_reviewers(
    store: GovernanceStore,
    repository: ScanRepository,
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    scan_database: Path,
    observation_id: int,
    first_reviewer_id: str,
    second_reviewer_id: str,
    adjudicator_id: str | None = None,
    now: datetime | None = None,
) -> ReviewAssignment:
    """Assign two independent reviewers and an optional distinct adjudicator."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    campaign = store.get_campaign(campaign_id)
    if campaign.status != "active":
        raise GovernanceStateError("Reviewers can be assigned only to active campaigns.")
    resolved_database = str(scan_database.expanduser().resolve())
    observation = repository.get_observation(observation_id)
    linked_scan = next(
        (
            item
            for item in store.list_scans(campaign_id)
            if item.scan_database == resolved_database and item.scan_id == observation.scan_id
        ),
        None,
    )
    if linked_scan is None:
        raise GovernancePolicyError("Observation does not belong to a linked campaign scan.")
    application = store.get_application(linked_scan.application_id)
    first = _require_assignment_identity(
        store,
        first_reviewer_id,
        role="reviewer",
        application=application,
        campaign=campaign,
    )
    second = _require_assignment_identity(
        store,
        second_reviewer_id,
        role="reviewer",
        application=application,
        campaign=campaign,
    )
    if first.reviewer_id == second.reviewer_id:
        raise GovernancePolicyError("Primary reviewers must be distinct identities.")
    adjudicator = None
    if adjudicator_id is not None:
        adjudicator = _require_assignment_identity(
            store,
            adjudicator_id,
            role="adjudicator",
            application=application,
            campaign=campaign,
        )
        if adjudicator.reviewer_id in {first.reviewer_id, second.reviewer_id}:
            raise GovernancePolicyError(
                "The adjudicator must be distinct from both primary reviewers."
            )
    data: dict[str, object] = {
        "campaign_id": campaign.campaign_id,
        "application_id": application.application_id,
        "scan_database": resolved_database,
        "scan_id": observation.scan_id,
        "observation_id": observation.id,
        "primary_reviewers": (first.reviewer_id, second.reviewer_id),
        "adjudicator_id": adjudicator.reviewer_id if adjudicator else None,
        "assigned_by": actor.reviewer_id,
        "assigned_at": _now(now),
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = assignment_record_sha256(data)
    return store.create_assignment(ReviewAssignment.model_validate(data))


def _decision_sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ensure_existing_decisions_are_attested(
    store: GovernanceStore,
    repository: ScanRepository,
    assignment: ReviewAssignment,
) -> None:
    case = repository.get_review_case(assignment.observation_id)
    attestations = store.list_attestations(
        assignment.campaign_id,
        scan_database=assignment.scan_database,
        observation_id=assignment.observation_id,
    )
    primary_by_actor = {item.actor_id: item for item in attestations if item.role == "primary"}
    for decision in case.decisions:
        attestation = primary_by_actor.get(decision.reviewer_id)
        if attestation is None:
            raise GovernancePolicyError(
                "The repository contains an unattested review decision; governed review "
                "cannot adopt legacy or bypassed decisions."
            )
        digest = _decision_sha256(decision.model_dump(mode="json"))
        if digest != attestation.repository_decision_sha256:
            raise GovernancePolicyError("A repository review decision changed after attestation.")
    if case.adjudication is not None:
        matching = [
            item
            for item in attestations
            if item.role == "adjudicator" and item.actor_id == case.adjudication.adjudicator_id
        ]
        if len(matching) != 1:
            raise GovernancePolicyError("Repository adjudication is not governed-attested.")
        digest = _decision_sha256(case.adjudication.model_dump(mode="json"))
        if digest != matching[0].repository_decision_sha256:
            raise GovernancePolicyError("Repository adjudication changed after attestation.")


def submit_governed_review(
    store: GovernanceStore,
    repository: ScanRepository,
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    scan_database: Path,
    observation_id: int,
    outcome: ReviewOutcome,
    note: str | None = None,
    now: datetime | None = None,
) -> ReviewAttestation:
    """Authenticate an assigned primary reviewer and attest the repository decision."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="reviewer",
    )
    campaign = store.get_campaign(campaign_id)
    if campaign.status != "active":
        raise GovernanceStateError("Reviews can be submitted only to active campaigns.")
    resolved_database = str(scan_database.expanduser().resolve())
    assignment = store.get_assignment(campaign_id, resolved_database, observation_id)
    if actor.reviewer_id not in assignment.primary_reviewers:
        raise GovernancePolicyError("Reviewer is not assigned to this observation.")
    _ensure_existing_decisions_are_attested(store, repository, assignment)
    case = repository.submit_review_decision(
        observation_id,
        actor.reviewer_id,
        outcome,
        note=note,
    )
    decision = next(item for item in case.decisions if item.reviewer_id == actor.reviewer_id)
    decision_digest = _decision_sha256(decision.model_dump(mode="json"))
    data: dict[str, object] = {
        "attestation_id": f"attest-{uuid4().hex[:20]}",
        "campaign_id": campaign.campaign_id,
        "scan_database": resolved_database,
        "observation_id": observation_id,
        "actor_id": actor.reviewer_id,
        "role": "primary",
        "outcome": decision.outcome,
        "repository_decision_id": decision.id,
        "repository_decision_sha256": decision_digest,
        "created_at": _now(now),
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = attestation_record_sha256(data)
    return store.create_attestation(ReviewAttestation.model_validate(data))


def adjudicate_governed_review(
    store: GovernanceStore,
    repository: ScanRepository,
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    scan_database: Path,
    observation_id: int,
    outcome: ReviewOutcome,
    rationale: str,
    now: datetime | None = None,
) -> ReviewAttestation:
    """Authenticate the assigned adjudicator and attest a disputed-case resolution."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="adjudicator",
    )
    campaign = store.get_campaign(campaign_id)
    if campaign.status != "active":
        raise GovernanceStateError("Adjudication requires an active campaign.")
    resolved_database = str(scan_database.expanduser().resolve())
    assignment = store.get_assignment(campaign_id, resolved_database, observation_id)
    if assignment.adjudicator_id is None:
        raise GovernancePolicyError("This assignment has no designated adjudicator.")
    if actor.reviewer_id != assignment.adjudicator_id:
        raise GovernancePolicyError("Actor is not the assigned adjudicator.")
    _ensure_existing_decisions_are_attested(store, repository, assignment)
    case = repository.get_review_case(observation_id)
    if case.state != "disputed":
        raise GovernanceStateError("Only a disputed review case can be adjudicated.")
    case = repository.adjudicate_review(
        observation_id,
        actor.reviewer_id,
        outcome,
        rationale=rationale,
    )
    if case.adjudication is None:
        raise GovernanceStateError("Repository did not produce an adjudication record.")
    decision_digest = _decision_sha256(case.adjudication.model_dump(mode="json"))
    data: dict[str, object] = {
        "attestation_id": f"attest-{uuid4().hex[:20]}",
        "campaign_id": campaign.campaign_id,
        "scan_database": resolved_database,
        "observation_id": observation_id,
        "actor_id": actor.reviewer_id,
        "role": "adjudicator",
        "outcome": case.adjudication.outcome,
        "repository_decision_id": case.adjudication.id,
        "repository_decision_sha256": decision_digest,
        "created_at": _now(now),
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = attestation_record_sha256(data)
    return store.create_attestation(ReviewAttestation.model_validate(data))


def assess_release(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    repositories: dict[str, ScanRepository],
    *,
    campaign_id: str,
    now: datetime | None = None,
    require_completed: bool = True,
) -> ReleaseAssessment:
    """Evaluate all identity, authorization, diversity, and review release gates."""
    campaign = store.get_campaign(campaign_id)
    reasons: list[str] = []
    if require_completed and campaign.status != "completed":
        reasons.append("campaign is not completed")
    elif not require_completed and campaign.status != "active":
        reasons.append("campaign is not active")

    applications = store.list_applications(campaign_id)
    scans = store.list_scans(campaign_id)
    assignments = store.list_assignments(campaign_id)
    families = {item.application_family for item in applications}
    if len(applications) < campaign.minimum_applications:
        reasons.append("minimum application count is not met")
    if len(families) < campaign.minimum_application_families:
        reasons.append("minimum application-family diversity is not met")

    current_time = _now(now)
    for application in applications:
        try:
            authorization = authorization_store.get(application.authorization_id)
            _authorization_is_current(authorization, now=current_time)
        except (AuthorizationError, GovernancePolicyError, ValueError) as exc:
            reasons.append(
                f"authorization {application.authorization_id} is not release-eligible: {exc}"
            )
            continue
        if authorization.record_sha256 != application.authorization_record_sha256:
            reasons.append(f"authorization {application.authorization_id} changed after approval")

    linked_refs = {(item.scan_database, item.scan_id): item for item in scans}
    all_observations: dict[tuple[str, int], object] = {}
    for scan in scans:
        repository = repositories.get(scan.scan_database)
        if repository is None:
            reasons.append(f"scan repository is unavailable: {scan.scan_database}")
            continue
        try:
            current_scan = repository.get_scan(scan.scan_id)
        except ValueError as exc:
            reasons.append(str(exc))
            continue
        if scan_snapshot_sha256(current_scan) != scan.scan_snapshot_sha256:
            reasons.append(f"scan {scan.scan_database}#{scan.scan_id} changed after linking")
        observations = repository.list_observations(
            scan_id=scan.scan_id,
            limit=1_000,
        )
        if len(observations) != scan.observations_count:
            reasons.append(f"scan {scan.scan_database}#{scan.scan_id} observation count changed")
        for observation in observations:
            all_observations[(scan.scan_database, observation.id)] = observation

    assignment_refs = {(item.scan_database, item.observation_id): item for item in assignments}
    missing_assignments = sorted(set(all_observations) - set(assignment_refs))
    if missing_assignments:
        reasons.append(f"{len(missing_assignments)} observations lack governed assignments")
    unknown_assignments = sorted(set(assignment_refs) - set(all_observations))
    if unknown_assignments:
        reasons.append(f"{len(unknown_assignments)} assignments reference absent observations")

    final_review_count = 0
    for _reference, assignment in assignment_refs.items():
        repository = repositories.get(assignment.scan_database)
        if repository is None:
            continue
        try:
            _ensure_existing_decisions_are_attested(store, repository, assignment)
            case = repository.get_review_case(assignment.observation_id)
        except Exception as exc:
            reasons.append(
                f"review {assignment.scan_database}#{assignment.observation_id} is invalid: {exc}"
            )
            continue
        if case.state not in {"consensus", "adjudicated"}:
            reasons.append(
                f"review {assignment.scan_database}#{assignment.observation_id} is {case.state}"
            )
            continue
        for reviewer_id in assignment.primary_reviewers:
            identity = store.get_identity(reviewer_id)
            if identity.status == "revoked":
                reasons.append(f"reviewer {reviewer_id} was revoked")
        if assignment.adjudicator_id and case.state == "adjudicated":
            identity = store.get_identity(assignment.adjudicator_id)
            if identity.status == "revoked":
                reasons.append(f"adjudicator {identity.reviewer_id} was revoked")
        final_review_count += 1

    if len(all_observations) < campaign.minimum_reviewed_observations:
        reasons.append("minimum reviewed observation count is not met")
    if final_review_count != len(all_observations):
        reasons.append("not every collected observation has a final governed review")

    unique_reasons = tuple(dict.fromkeys(reasons))
    return ReleaseAssessment(
        campaign_id=campaign_id,
        ready=not unique_reasons,
        reasons=unique_reasons,
        application_count=len(applications),
        application_family_count=len(families),
        scan_count=len(linked_refs),
        observation_count=len(all_observations),
        final_review_count=final_review_count,
    )


def complete_campaign(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    repositories: dict[str, ScanRepository],
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    now: datetime | None = None,
) -> CampaignRecord:
    """Complete a campaign only after every non-status release gate passes."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    assessment = assess_release(
        store,
        authorization_store,
        repositories,
        campaign_id=campaign_id,
        now=now,
        require_completed=False,
    )
    if not assessment.ready:
        raise GovernancePolicyError("Campaign cannot complete: " + "; ".join(assessment.reasons))
    campaign = store.get_campaign(campaign_id)
    data = campaign.model_dump()
    data.update(
        {
            "status": "completed",
            "completed_at": _now(now),
            "record_sha256": "0" * 64,
        }
    )
    data["record_sha256"] = campaign_record_sha256(data)
    replacement = CampaignRecord.model_validate(data)
    return store.replace_campaign(
        replacement,
        actor_id=actor.reviewer_id,
        event_type="completed",
        detail={"final_review_count": assessment.final_review_count},
    )


def release_dataset(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    repositories: dict[str, ScanRepository],
    *,
    actor_id: str,
    actor_secret: str,
    campaign_id: str,
    now: datetime | None = None,
) -> DatasetReleaseManifest:
    """Create one immutable release manifest after all release gates pass."""
    actor = authenticate_identity(
        store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    assessment = assess_release(
        store,
        authorization_store,
        repositories,
        campaign_id=campaign_id,
        now=now,
        require_completed=True,
    )
    if not assessment.ready:
        raise GovernancePolicyError("Dataset release is blocked: " + "; ".join(assessment.reasons))
    campaign = store.get_campaign(campaign_id)
    applications = store.list_applications(campaign_id)
    scans = store.list_scans(campaign_id)
    assignments = store.list_assignments(campaign_id)
    labels: dict[str, ReviewOutcome] = {}
    references: list[str] = []
    for assignment in assignments:
        repository = repositories[assignment.scan_database]
        case = repository.get_review_case(assignment.observation_id)
        reference = f"{assignment.scan_database}#{assignment.observation_id}"
        references.append(reference)
        labels[reference] = cast(ReviewOutcome, case.effective_label)
    data: dict[str, object] = {
        "release_id": f"release-{uuid4().hex[:20]}",
        "campaign_id": campaign.campaign_id,
        "campaign_record_sha256": campaign.record_sha256,
        "campaign_manifest_sha256": campaign.approved_manifest_sha256,
        "application_ids": tuple(
            item.application_id
            for item in sorted(applications, key=lambda value: value.application_id)
        ),
        "scan_references": tuple(
            f"{item.scan_database}#{item.scan_id}"
            for item in sorted(scans, key=lambda value: (value.scan_database, value.scan_id))
        ),
        "observation_references": tuple(sorted(references)),
        "effective_labels": {key: labels[key] for key in sorted(labels)},
        "released_by": actor.reviewer_id,
        "released_at": _now(now),
        "manifest_sha256": "0" * 64,
    }
    if data["campaign_manifest_sha256"] is None:
        raise GovernanceStateError("Completed campaign has no approved manifest digest.")
    data["manifest_sha256"] = release_manifest_sha256(data)
    return store.create_release(DatasetReleaseManifest.model_validate(data))
