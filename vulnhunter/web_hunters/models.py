"""Immutable contracts for advisory web-hunter hypotheses and review intents."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_perception.models import ApplicationSurfaceGraph, BrowserPerceptionEvidence

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class HypothesisState(StrEnum):
    """States available before a separate verifier exists."""

    SUSPECTED = "suspected"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class HunterRunStatus(StrEnum):
    COMPLETED = "completed"
    ABSTAINED = "abstained"


class VerificationStrategy(StrEnum):
    OBJECT_AUTHORIZATION_REVIEW = "object_authorization_review"
    REQUEST_INTEGRITY_REVIEW = "request_integrity_review"
    FILE_UPLOAD_REVIEW = "file_upload_review"
    AUTHENTICATION_REVIEW = "authentication_review"
    API_ACCESS_REVIEW = "api_access_review"


class HunterBudget(BaseModel):
    """Hard output ceilings for one coordinator pass."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_hypotheses: int = Field(default=40, ge=1, le=500)
    maximum_hypotheses_per_hunter: int = Field(default=12, ge=1, le=100)

    @model_validator(mode="after")
    def validate_budget(self):
        if self.maximum_hypotheses_per_hunter > self.maximum_hypotheses:
            raise ValueError("per-hunter hypothesis ceiling cannot exceed the run ceiling")
        return self


class HunterEvidenceReference(BaseModel):
    """Graph-bound evidence identifiers; raw target content is never carried here."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    graph_sha256: str
    node_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    edge_ids: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("graph_sha256")
    @classmethod
    def validate_graph_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("graph_sha256 must be a SHA-256 digest")
        return value

    @field_validator("node_ids", "edge_ids")
    @classmethod
    def validate_reference_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("hunter evidence identifiers must be SHA-256 digests")
        if len(set(values)) != len(values):
            raise ValueError("hunter evidence identifiers must be unique")
        return values


class VerificationIntent(BaseModel):
    """A semantic review plan that deliberately has no execution authority."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intent_id: str
    hypothesis_id: str
    strategy: VerificationStrategy
    target_node_id: str
    execution_enabled: Literal[False] = False
    requires_authorization: Literal[True] = True
    network_access_allowed: Literal[False] = False
    mutating_requests_allowed: Literal[False] = False
    credential_guessing_allowed: Literal[False] = False
    authorization_bypass_allowed: Literal[False] = False
    shell_execution_allowed: Literal[False] = False
    required_evidence: tuple[str, ...] = Field(min_length=1, max_length=12)

    @field_validator("intent_id", "hypothesis_id", "target_node_id")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verification identifiers must be SHA-256 digests")
        return value

    @field_validator("required_evidence")
    @classmethod
    def validate_evidence_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_IDENTIFIER.fullmatch(value) is None for value in values):
            raise ValueError("required evidence names must be stable lowercase identifiers")
        if len(set(values)) != len(values):
            raise ValueError("required evidence names must be unique")
        return values


class HunterHypothesis(BaseModel):
    """One bounded, advisory suspicion derived from sanitized browser structure."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis_id: str
    semantic_fingerprint: str
    hunter_id: str
    vulnerability_class: str = Field(min_length=3, max_length=80)
    title: str = Field(min_length=3, max_length=160)
    observation: str = Field(min_length=3, max_length=500)
    rationale: str = Field(min_length=3, max_length=1_000)
    target_node_id: str
    priority_score: int = Field(ge=0, le=100)
    state: HypothesisState = HypothesisState.SUSPECTED
    evidence: HunterEvidenceReference
    verification_intent: VerificationIntent
    content_trust: Literal["derived_from_untrusted_target_structure"] = (
        "derived_from_untrusted_target_structure"
    )

    @field_validator("hypothesis_id", "semantic_fingerprint", "target_node_id")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("hypothesis identifiers must be SHA-256 digests")
        return value

    @field_validator("hunter_id", "vulnerability_class")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("hunter identifiers must be stable lowercase values")
        return value

    @field_validator("title", "observation", "rationale")
    @classmethod
    def validate_single_line_text(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if any(ord(character) < 32 for character in normalized):
            raise ValueError("hypothesis text must not contain control characters")
        return normalized

    @model_validator(mode="after")
    def validate_intent_binding(self):
        if self.state is not HypothesisState.SUSPECTED:
            raise ValueError("this coordinator may emit suspected hypotheses only")
        if self.verification_intent.hypothesis_id != self.hypothesis_id:
            raise ValueError("verification intent must bind the exact hypothesis")
        if self.verification_intent.target_node_id != self.target_node_id:
            raise ValueError("verification intent must bind the exact target node")
        return self


class HunterExecutionSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hunter_id: str
    status: HunterRunStatus
    emitted_hypotheses: int = Field(ge=0)
    dropped_hypotheses: int = Field(ge=0)

    @field_validator("hunter_id")
    @classmethod
    def validate_hunter_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("hunter_id must be a stable lowercase identifier")
        return value


class HunterContext(BaseModel):
    """Validated, read-only perception input available to specialist hunters."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    target_url: str = Field(max_length=2_048)
    perception_plan_sha256: str
    perception_evidence_sha256: str
    graph_sha256: str
    evidence: BrowserPerceptionEvidence
    graph: ApplicationSurfaceGraph

    @field_validator("perception_plan_sha256", "perception_evidence_sha256", "graph_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("hunter source identities must be SHA-256 digests")
        return value


class HunterRunResult(BaseModel):
    """Integrity-linked coordinator output; it contains no executable action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_url: str = Field(max_length=2_048)
    perception_plan_sha256: str
    perception_evidence_sha256: str
    graph_sha256: str
    started_at: datetime
    completed_at: datetime
    budget: HunterBudget
    hypotheses: tuple[HunterHypothesis, ...]
    hunter_summaries: tuple[HunterExecutionSummary, ...]
    dropped_hypotheses: int = Field(ge=0)
    result_sha256: str

    @field_validator(
        "perception_plan_sha256",
        "perception_evidence_sha256",
        "graph_sha256",
        "result_sha256",
    )
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("hunter result identities must be SHA-256 digests")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("hunter timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_result(self):
        if self.completed_at < self.started_at:
            raise ValueError("hunter run cannot complete before it starts")
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        fingerprints = [item.semantic_fingerprint for item in self.hypotheses]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("hunter hypothesis IDs must be unique")
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("hunter semantic fingerprints must be unique")
        if len(self.hypotheses) > self.budget.maximum_hypotheses:
            raise ValueError("hunter result exceeds its hypothesis budget")
        expected = sha256_json(self.model_dump(mode="json", exclude={"result_sha256"}))
        if expected != self.result_sha256:
            raise ValueError("hunter result integrity hash does not match its contents")
        return self


def semantic_fingerprint(
    *,
    hunter_id: str,
    vulnerability_class: str,
    target_node_id: str,
    strategy: VerificationStrategy,
) -> str:
    return sha256_json(
        {
            "hunter_id": hunter_id,
            "vulnerability_class": vulnerability_class,
            "target_node_id": target_node_id,
            "strategy": strategy.value,
        }
    )


def hypothesis_id_for(*, graph_sha256: str, semantic_fingerprint_value: str) -> str:
    return sha256_json(
        {
            "graph_sha256": graph_sha256,
            "semantic_fingerprint": semantic_fingerprint_value,
        }
    )


def verification_intent_id_for(
    *,
    hypothesis_id: str,
    strategy: VerificationStrategy,
    target_node_id: str,
) -> str:
    return sha256_json(
        {
            "hypothesis_id": hypothesis_id,
            "strategy": strategy.value,
            "target_node_id": target_node_id,
        }
    )
