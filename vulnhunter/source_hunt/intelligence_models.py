"""Immutable Source Hunt Intelligence V2 contracts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.source_hunt.models import RepositorySnapshot, SourceCandidate, SourceReference


class HunterRole(StrEnum):
    INJECTION = "injection"
    ACCESS_CONTROL = "access_control"
    NAVIGATION = "navigation"
    NETWORK_BOUNDARY = "network_boundary"
    DESERIALIZATION = "deserialization"
    BUSINESS_LOGIC = "business_logic"
    CRYPTOGRAPHY = "cryptography"
    SINK_BACKSTOP = "sink_backstop"


class AnalysisCoverage(StrEnum):
    PRODUCTION = "production"
    INVENTORY_ONLY = "inventory_only"
    UNSUPPORTED = "unsupported"


class SpecialistAssignment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    surface_id: str
    primary_role: HunterRole
    independent_roles: tuple[HunterRole, ...]
    reason: str = Field(min_length=3, max_length=1_000)


class LanguageInventoryItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    language: str
    file_count: int = Field(ge=0)
    coverage: AnalysisCoverage


class RepositoryGraphSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    python_files: int = Field(ge=0)
    classes: int = Field(ge=0)
    functions: int = Field(ge=0)
    call_edges: int = Field(ge=0)
    self_method_edges: int = Field(ge=0)
    ambiguous_calls: int = Field(ge=0)
    unresolved_calls: int = Field(ge=0)


class RootCauseFingerprint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    vulnerability_class: str = Field(min_length=2, max_length=80)
    sink_kind: str = Field(min_length=2, max_length=80)
    entry_kind: str = Field(min_length=2, max_length=80)
    guard_count: int = Field(ge=0)
    fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RootCauseOccurrence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    surface_id: str
    entry_point: SourceReference
    sink: SourceReference
    sink_kind: str
    same_guard_shape: bool


class RootCauseSweep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    fingerprint: RootCauseFingerprint
    occurrences: tuple[RootCauseOccurrence, ...]
    truncated: bool = False


class SecurityProofPlan(BaseModel):
    """Non-executing plan for a later developer-led RED/GREEN proof."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    proof_plan_id: str = Field(pattern=r"^proof-[0-9a-f]{24}$")
    candidate_id: str
    original_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_files: tuple[str, ...]
    red_security_test: str = Field(min_length=3, max_length=4_000)
    green_verification: str = Field(min_length=3, max_length=4_000)
    original_condition: str = Field(min_length=3, max_length=2_000)
    required_verifiers: tuple[str, ...]
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        candidate: SourceCandidate,
        snapshot: RepositorySnapshot,
    ) -> SecurityProofPlan:
        if candidate.remediation is None:
            raise ValueError("proof planning requires a remediation proposal")
        required = (
            "security_regression",
            "original_condition_blocked",
            "broader_regression_suite",
            "fixed_snapshot_reference_integrity",
        )
        canonical = {
            "candidate_id": candidate.candidate_id,
            "original_snapshot_sha256": snapshot.snapshot_sha256,
            "target_files": list(candidate.remediation.target_files),
            "red_security_test": candidate.remediation.regression_test,
            "green_verification": candidate.remediation.verification_recipe,
            "original_condition": candidate.hypothesis.summary,
            "required_verifiers": list(required),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(
            proof_plan_id=f"proof-{digest[:24]}",
            candidate_id=candidate.candidate_id,
            original_snapshot_sha256=snapshot.snapshot_sha256,
            target_files=candidate.remediation.target_files,
            red_security_test=candidate.remediation.regression_test,
            green_verification=candidate.remediation.verification_recipe,
            original_condition=candidate.hypothesis.summary,
            required_verifiers=required,
            plan_sha256=digest,
        )

    @model_validator(mode="after")
    def verify_digest(self) -> SecurityProofPlan:
        canonical = {
            "candidate_id": self.candidate_id,
            "original_snapshot_sha256": self.original_snapshot_sha256,
            "target_files": list(self.target_files),
            "red_security_test": self.red_security_test,
            "green_verification": self.green_verification,
            "original_condition": self.original_condition,
            "required_verifiers": list(self.required_verifiers),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != self.plan_sha256:
            raise ValueError("security proof-plan digest does not match its contents")
        if self.proof_plan_id != f"proof-{digest[:24]}":
            raise ValueError("security proof-plan ID does not match its digest")
        return self


class SourceHuntIntelligenceBundle(BaseModel):
    """Sidecar intelligence that never upgrades a finding's authority."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str = Field(pattern=r"^source-report-[0-9a-f]{24}$")
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    engine_version: str = "source-hunt-intelligence-v2"
    specialist_assignments: tuple[SpecialistAssignment, ...]
    root_cause_sweeps: tuple[RootCauseSweep, ...]
    proof_plans: tuple[SecurityProofPlan, ...]
    graph_summary: RepositoryGraphSummary
    language_inventory: tuple[LanguageInventoryItem, ...]
    created_at: datetime
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        report_id: str,
        snapshot_sha256: str,
        specialist_assignments: tuple[SpecialistAssignment, ...],
        root_cause_sweeps: tuple[RootCauseSweep, ...],
        proof_plans: tuple[SecurityProofPlan, ...],
        graph_summary: RepositoryGraphSummary,
        language_inventory: tuple[LanguageInventoryItem, ...],
        created_at: datetime,
    ) -> SourceHuntIntelligenceBundle:
        canonical = {
            "report_id": report_id,
            "snapshot_sha256": snapshot_sha256,
            "engine_version": "source-hunt-intelligence-v2",
            "specialist_assignments": [
                item.model_dump(mode="json") for item in specialist_assignments
            ],
            "root_cause_sweeps": [item.model_dump(mode="json") for item in root_cause_sweeps],
            "proof_plans": [item.model_dump(mode="json") for item in proof_plans],
            "graph_summary": graph_summary.model_dump(mode="json"),
            "language_inventory": [item.model_dump(mode="json") for item in language_inventory],
            "created_at": created_at.isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(**canonical, bundle_sha256=digest)

    @model_validator(mode="after")
    def verify_bundle_digest(self) -> SourceHuntIntelligenceBundle:
        canonical = {
            "report_id": self.report_id,
            "snapshot_sha256": self.snapshot_sha256,
            "engine_version": self.engine_version,
            "specialist_assignments": [
                item.model_dump(mode="json") for item in self.specialist_assignments
            ],
            "root_cause_sweeps": [item.model_dump(mode="json") for item in self.root_cause_sweeps],
            "proof_plans": [item.model_dump(mode="json") for item in self.proof_plans],
            "graph_summary": self.graph_summary.model_dump(mode="json"),
            "language_inventory": [
                item.model_dump(mode="json") for item in self.language_inventory
            ],
            "created_at": self.created_at.isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != self.bundle_sha256:
            raise ValueError("source-hunt intelligence bundle digest does not match its contents")
        return self
