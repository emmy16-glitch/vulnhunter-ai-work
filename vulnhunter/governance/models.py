"""Immutable models for governed collection campaigns and reviewer identities."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

IdentityRole = Literal["campaign_admin", "reviewer", "adjudicator"]
IdentityStatus = Literal["active", "disabled", "revoked"]
CampaignStatus = Literal[
    "draft",
    "approved",
    "active",
    "completed",
    "cancelled",
]
AssignmentRole = Literal["primary", "adjudicator"]
ReviewOutcome = Literal["confirmed", "false_positive"]
AttestationRole = Literal["primary", "adjudicator"]


class ReviewerIdentity(BaseModel):
    """Authenticated local reviewer or governance administrator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reviewer_id: str = Field(min_length=2, max_length=64)
    display_name: str = Field(min_length=1, max_length=200)
    roles: tuple[IdentityRole, ...] = Field(min_length=1)
    conflict_tags: tuple[str, ...] = ()
    status: IdentityStatus = "active"
    credential_salt: str = Field(pattern=r"^[A-Za-z0-9_-]{20,}$")
    credential_hash: str = Field(pattern=r"^[A-Za-z0-9_-]{40,}$")
    created_by: str = Field(min_length=2, max_length=64)
    created_at: datetime
    status_changed_at: datetime | None = None
    status_reason: str | None = Field(default=None, max_length=2_000)
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at", "status_changed_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Identity timestamps must include a timezone.")
        return value.astimezone(UTC)


class CampaignLimits(BaseModel):
    """Collection ceilings that must not exceed target authorization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_pages: int = Field(ge=1, le=500)
    maximum_depth: int = Field(ge=0, le=10)
    maximum_requests: int = Field(ge=1, le=10_000)
    minimum_request_delay_seconds: float = Field(ge=0, le=10)
    maximum_scans_per_application: int = Field(default=10, ge=1, le=1_000)


class CampaignRecord(BaseModel):
    """One governed real-data collection campaign."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str = Field(min_length=8, max_length=80)
    title: str = Field(min_length=1, max_length=300)
    purpose: str = Field(min_length=1, max_length=2_000)
    owner_id: str = Field(min_length=2, max_length=64)
    created_by: str = Field(min_length=2, max_length=64)
    created_at: datetime
    limits: CampaignLimits
    minimum_applications: int = Field(default=2, ge=1, le=1_000)
    minimum_application_families: int = Field(default=2, ge=1, le=1_000)
    minimum_reviewed_observations: int = Field(default=20, ge=1, le=1_000_000)
    status: CampaignStatus = "draft"
    approved_by: str | None = Field(default=None, min_length=2, max_length=64)
    approved_at: datetime | None = None
    approved_manifest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    completed_at: datetime | None = None
    cancelled_at: datetime | None = None
    cancellation_reason: str | None = Field(default=None, max_length=2_000)
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "created_at",
        "approved_at",
        "completed_at",
        "cancelled_at",
    )
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Campaign timestamps must include a timezone.")
        return value.astimezone(UTC)


class CampaignApplication(BaseModel):
    """One authorized application enrolled in a campaign draft."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_id: str = Field(min_length=8, max_length=80)
    campaign_id: str = Field(min_length=8, max_length=80)
    application_family: str = Field(min_length=1, max_length=200)
    environment: str = Field(min_length=1, max_length=200)
    target_url: str = Field(min_length=1, max_length=2_000)
    authorization_id: str = Field(min_length=8, max_length=80)
    authorization_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    conflict_tags: tuple[str, ...] = ()
    registered_by: str = Field(min_length=2, max_length=64)
    registered_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("registered_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Application timestamps must include a timezone.")
        return value.astimezone(UTC)


class CampaignScan(BaseModel):
    """Evidence that one completed scan belongs to a campaign application."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str = Field(min_length=8, max_length=80)
    application_id: str = Field(min_length=8, max_length=80)
    scan_database: str = Field(min_length=1, max_length=2_000)
    scan_id: int = Field(ge=1)
    target_url: str = Field(min_length=1, max_length=2_000)
    pages_visited: int = Field(ge=0)
    observations_count: int = Field(ge=0)
    validation_event_id: int = Field(ge=1)
    scan_started_event_id: int = Field(ge=1)
    scan_completed_event_id: int = Field(ge=1)
    scan_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    linked_by: str = Field(min_length=2, max_length=64)
    linked_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("linked_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Scan timestamps must include a timezone.")
        return value.astimezone(UTC)


class ReviewAssignment(BaseModel):
    """Identity-bound assignment for one observed finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str = Field(min_length=8, max_length=80)
    application_id: str = Field(min_length=8, max_length=80)
    scan_database: str = Field(min_length=1, max_length=2_000)
    scan_id: int = Field(ge=1)
    observation_id: int = Field(ge=1)
    primary_reviewers: tuple[str, str]
    adjudicator_id: str | None = Field(default=None, min_length=2, max_length=64)
    assigned_by: str = Field(min_length=2, max_length=64)
    assigned_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("assigned_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Assignment timestamps must include a timezone.")
        return value.astimezone(UTC)


class ReviewAttestation(BaseModel):
    """Proof that an authenticated assigned identity produced a repository decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    attestation_id: str = Field(min_length=8, max_length=80)
    campaign_id: str = Field(min_length=8, max_length=80)
    scan_database: str = Field(min_length=1, max_length=2_000)
    observation_id: int = Field(ge=1)
    actor_id: str = Field(min_length=2, max_length=64)
    role: AttestationRole
    outcome: ReviewOutcome
    repository_decision_id: int = Field(ge=1)
    repository_decision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Attestation timestamps must include a timezone.")
        return value.astimezone(UTC)


class GovernanceEvent(BaseModel):
    """One redacted hash-chained governance event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: int = Field(ge=1)
    subject_type: str = Field(min_length=1, max_length=50)
    subject_id: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    actor_id: str = Field(min_length=2, max_length=64)
    occurred_at: datetime
    detail: dict[str, object]
    previous_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Event timestamps must include a timezone.")
        return value.astimezone(UTC)


class ReleaseAssessment(BaseModel):
    """Deterministic result of evaluating campaign release eligibility."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    ready: bool
    reasons: tuple[str, ...]
    application_count: int = Field(ge=0)
    application_family_count: int = Field(ge=0)
    scan_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    final_review_count: int = Field(ge=0)


class DatasetReleaseManifest(BaseModel):
    """Immutable provenance manifest for a governed campaign dataset release."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    release_id: str = Field(min_length=8, max_length=80)
    campaign_id: str = Field(min_length=8, max_length=80)
    campaign_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    application_ids: tuple[str, ...]
    scan_references: tuple[str, ...]
    observation_references: tuple[str, ...]
    effective_labels: dict[str, ReviewOutcome]
    released_by: str = Field(min_length=2, max_length=64)
    released_at: datetime
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("released_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Release timestamps must include a timezone.")
        return value.astimezone(UTC)


def canonical_sha256(value: BaseModel | dict[str, object], *, exclude: set[str]) -> str:
    """Hash a Pydantic model or mapping using canonical JSON."""
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json", exclude=exclude)
    else:
        raw = {key: item for key, item in value.items() if key not in exclude}
        payload = TypeAdapter(dict[str, object]).dump_python(raw, mode="json")
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def identity_record_sha256(value: ReviewerIdentity | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"record_sha256"})


def campaign_record_sha256(value: CampaignRecord | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"record_sha256"})


def application_record_sha256(value: CampaignApplication | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"record_sha256"})


def campaign_scan_record_sha256(value: CampaignScan | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"record_sha256"})


def assignment_record_sha256(value: ReviewAssignment | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"record_sha256"})


def attestation_record_sha256(value: ReviewAttestation | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"record_sha256"})


def release_manifest_sha256(value: DatasetReleaseManifest | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"manifest_sha256"})


def campaign_manifest_sha256(
    campaign: CampaignRecord,
    applications: tuple[CampaignApplication, ...],
) -> str:
    """Hash immutable campaign intent and its ordered authorization bindings."""
    payload = {
        "campaign": campaign.model_dump(
            mode="json",
            include={
                "campaign_id",
                "title",
                "purpose",
                "owner_id",
                "created_by",
                "created_at",
                "limits",
                "minimum_applications",
                "minimum_application_families",
                "minimum_reviewed_observations",
            },
        ),
        "applications": [
            item.model_dump(mode="json", exclude={"record_sha256"})
            for item in sorted(applications, key=lambda current: current.application_id)
        ],
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
