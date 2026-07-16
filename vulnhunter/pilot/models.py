"""Strict immutable models for a controlled local pilot plan."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PilotIdentityStatus = Literal[
    "active",
    "disabled",
    "revoked",
    "untrusted",
    "unavailable",
]


class PilotIdentity(BaseModel):
    """One declared human pilot identity and its local status."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    identity_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=200)
    status: PilotIdentityStatus
    human_controlled: bool = True


class PilotApplication(BaseModel):
    """One local/lab application planned for the pilot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_id: str = Field(min_length=1, max_length=128)
    application_family: str = Field(min_length=1, max_length=128)
    environment: Literal["local", "lab"]
    authorization_reference: str = Field(min_length=1, max_length=256)
    scope_reference: str = Field(min_length=1, max_length=256)
    target_reference: str = Field(min_length=1, max_length=256)


class PilotDatasetTargets(BaseModel):
    """Dataset-quality targets, separate from release eligibility."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    minimum_samples: int = Field(ge=2)
    minimum_per_class: int = Field(ge=1)
    required_classes: tuple[Literal["confirmed", "false_positive"], ...] = (
        "confirmed",
        "false_positive",
    )
    minimum_application_families: int = Field(ge=1)
    minimum_scans: int = Field(ge=1)
    minimum_scans_per_class: int = Field(ge=1)


class PilotRoleAssignments(BaseModel):
    """Human role separation for the controlled pilot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    operator_ids: tuple[str, ...] = Field(min_length=1)
    primary_reviewer_ids: tuple[str, str]
    adjudicator_id: str = Field(min_length=1)
    dataset_quality_auditor_id: str = Field(min_length=1)
    test_verifier_id: str = Field(min_length=1)
    release_authority_id: str = Field(min_length=1)
    emergency_stop_owner_id: str = Field(min_length=1)


class PilotRisk(BaseModel):
    """One known pilot risk and its mitigation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    risk: str = Field(min_length=1, max_length=500)
    mitigation: str = Field(min_length=1, max_length=1000)


class PilotPlan(BaseModel):
    """Versioned immutable plan for a local/lab-only human pilot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"]
    plan_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    title: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=1, max_length=2000)
    accountable_owner_id: str = Field(min_length=1, max_length=128)
    created_at: datetime
    review_by: date
    planned_start: datetime | None = None
    stop_conditions: tuple[str, ...] = Field(min_length=1)
    local_lab_only: bool

    authorization_references: tuple[str, ...] = Field(min_length=1)
    applications: tuple[PilotApplication, ...] = Field(min_length=1)
    prohibited_targets: tuple[str, ...] = Field(min_length=1)
    campaign_separation_plan: str = Field(min_length=1, max_length=2000)

    identities: tuple[PilotIdentity, ...] = Field(min_length=1)
    assignments: PilotRoleAssignments
    conflict_of_interest_declarations: dict[str, bool]

    evidence_retention_policy: str = Field(min_length=1, max_length=3000)
    sensitive_data_redaction_policy: str = Field(min_length=1, max_length=3000)
    duplicate_evidence_policy: str = Field(min_length=1, max_length=3000)
    reviewer_agreement_monitoring: str = Field(min_length=1, max_length=2000)
    disagreement_and_adjudication_procedure: str = Field(min_length=1, max_length=3000)
    rollback_and_incident_procedure: str = Field(min_length=1, max_length=3000)
    untrusted_content_policy: str = Field(min_length=1, max_length=2000)

    dataset_targets: PilotDatasetTargets

    connector_policy: Literal["disabled"]
    automatic_campaign_approval: bool
    automatic_vulnerability_confirmation: bool
    automatic_adjudication: bool
    automatic_release: bool
    model_training_during_collection: bool
    release_authority_is_human: bool

    known_risks: tuple[PilotRisk, ...] = Field(min_length=1)


class PilotReadinessReport(BaseModel):
    """Deterministic read-only validation evidence for one pilot plan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str
    assessed_at: datetime
    valid: bool
    hard_blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    informational_metrics: dict[str, object]
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
