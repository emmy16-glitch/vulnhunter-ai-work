"""Typed product-layer read models over existing VulnHunter services."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AvailabilityState(StrEnum):
    """Fail-closed availability state for one capability or store."""

    AVAILABLE = "available"
    EMPTY = "empty"
    MISSING = "missing"
    INVALID = "invalid"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"


class ApprovalState(StrEnum):
    """Approval state for one bounded agent action."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


class PolicyResultState(StrEnum):
    """Normalized policy decision state."""

    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"
    UNAVAILABLE = "unavailable"


class CapabilityStatus(BaseModel):
    """Availability and status text for one product capability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    state: AvailabilityState
    detail: str
    evidence_reference: str | None = None


class AuditActivitySummary(BaseModel):
    """Recent immutable audit activity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str
    subject: str
    event_type: str
    occurred_at: datetime
    actor_id: str | None = None
    evidence_reference: str | None = None


class ProductStatusSummary(BaseModel):
    """Current product/runtime/store status."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    blueprint_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    runtime_config_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    authorization_store: CapabilityStatus
    governance_store: CapabilityStatus
    role_registry: CapabilityStatus
    agent_runtime: CapabilityStatus
    readiness: CapabilityStatus
    audit_evidence: CapabilityStatus


class ReadinessSummary(BaseModel):
    """Governed pilot and model-readiness summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    pilot_ready: bool
    model_training_ready: bool
    hard_release_blockers: tuple[str, ...]
    model_training_blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    application_family_diversity: int | None = None
    class_balance: dict[str, int] = Field(default_factory=dict)
    review_agreement_count: int | None = None
    review_disagreement_count: int | None = None
    adjudication_count: int | None = None
    release_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    informational_metrics: dict[str, Any] = Field(default_factory=dict)


class CampaignSummary(BaseModel):
    """High-level governed campaign summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    status: str
    authorization_references: tuple[str, ...]
    scope_summary: tuple[str, ...]
    application_count: int = Field(ge=0)
    scan_count: int = Field(ge=0)
    assignment_count: int = Field(ge=0)
    review_state: dict[str, int] = Field(default_factory=dict)
    adjudication_state: dict[str, int] = Field(default_factory=dict)
    release_manifest_state: str
    readiness_state: str
    release_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    dataset_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    readiness_report_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class CampaignScanSummary(BaseModel):
    """Linked governed scan provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_id: str
    scan_database: str
    scan_id: int = Field(ge=1)
    target_url: str
    pages_visited: int = Field(ge=0)
    observations_count: int = Field(ge=0)
    validation_event_id: int = Field(ge=1)
    scan_started_event_id: int = Field(ge=1)
    scan_completed_event_id: int = Field(ge=1)
    scan_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReviewAssignmentSummary(BaseModel):
    """Governed review assignment summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_database: str
    observation_id: int = Field(ge=1)
    primary_reviewers: tuple[str, str]
    adjudicator_id: str | None = None
    state: str
    effective_label: str


class CampaignDetail(BaseModel):
    """Detailed governed campaign surface."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    status: str
    title: str
    purpose: str
    owner_id: str
    authorization_references: tuple[str, ...]
    scope_summary: tuple[str, ...]
    applications: tuple[dict[str, Any], ...]
    scans: tuple[CampaignScanSummary, ...]
    assignments: tuple[ReviewAssignmentSummary, ...]
    review_state: dict[str, int] = Field(default_factory=dict)
    adjudication_state: dict[str, int] = Field(default_factory=dict)
    release_manifest_state: str
    release_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    readiness: ReadinessSummary | None = None


class RoleSummary(BaseModel):
    """Role registry summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role_id: str
    display_name: str
    purpose: str
    version: str
    risk_level: str
    status: str
    trust_assumption: str
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    tool_ids: tuple[str, ...]
    human_approval_points: tuple[str, ...]
    connector_policy: str
    last_reviewed_on: str
    operational_state: str


class SkillSummary(BaseModel):
    """Skill registry summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    skill_id: str
    display_name: str
    purpose: str
    version: str
    risk_level: str
    status: str
    trust_assumption: str
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    required_tools: tuple[str, ...]
    last_reviewed_on: str
    operational_state: str


class RoleDetail(RoleSummary):
    """Detailed role registry surface."""

    data_permissions: tuple[dict[str, Any], ...]
    verification_requirements: tuple[str, ...]
    required_tests: tuple[str, ...]
    rollback_procedure: tuple[str, ...]
    skill_ids: tuple[str, ...]
    trust_warning: str


class SkillDetail(SkillSummary):
    """Detailed skill registry surface."""

    verification_requirements: tuple[str, ...]
    required_tests: tuple[str, ...]
    rollback_procedure: tuple[str, ...]


class AgentRunSummary(BaseModel):
    """Bounded agent runtime run summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    objective: str
    selected_role: str
    selected_skill: str | None = None
    current_state: str
    proposed_action: str | None = None
    requested_tool: str | None = None
    risk_classification: str | None = None
    policy_result: PolicyResultState
    policy_reason: str
    approval_requirement: bool
    approval_state: ApprovalState
    execution_state: str
    evaluation_result: str | None = None
    retry_decision: str | None = None
    created_at: datetime
    updated_at: datetime
    final_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    denial_or_failure_reason: str | None = None
    registry_validation_result: PolicyResultState = PolicyResultState.UNAVAILABLE
    registry_validation_reason: str = "Role and skill validation unavailable."
    workflow_state: str | None = None
    execution_enabled: Literal[False] = False
    execution_blocking_reason: str | None = None
    authorization_id: str | None = None
    plan_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    readiness: dict[str, Any] = Field(default_factory=dict)
    assessment_owner: str | None = None


class AgentRunDetail(AgentRunSummary):
    """Detailed bounded agent runtime surface."""

    planner_output: str | None = None
    input_summary: str | None = None
    scope_summary: str | None = None
    requested_operation: str | None = None
    audit_references: tuple[str, ...] = ()
    recent_events: tuple[dict[str, Any], ...] = ()
    command_plan_summary: dict[str, Any] = Field(default_factory=dict)
    findings: tuple[dict[str, Any], ...] = ()
    artifacts: tuple[dict[str, Any], ...] = ()
    attack_path: tuple[dict[str, Any], ...] = ()


class DashboardSummary(BaseModel):
    """Top-level operational dashboard read model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ProductStatusSummary
    campaign_totals_by_status: dict[str, int] = Field(default_factory=dict)
    pending_reviews: int | None = None
    pending_adjudications: int | None = None
    released_campaigns: int | None = None
    readiness_report_available: int | None = None
    pending_human_approvals: int | None = None
    recent_audit_activity: tuple[AuditActivitySummary, ...] = ()
