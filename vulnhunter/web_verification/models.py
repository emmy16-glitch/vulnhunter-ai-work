"""Immutable contracts for independent, read-only web verification."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_hunters.models import VerificationStrategy

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class VerificationVerdict(StrEnum):
    """Verdicts reserved for the independent verification lifecycle."""

    VALIDATED = "validated"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class VerificationReason(StrEnum):
    """Machine-readable reasons emitted by the passive verifier foundation."""

    PASSIVE_EVIDENCE_INSUFFICIENT = "passive_evidence_insufficient"
    STRUCTURAL_PREDICATE_NOT_REPRODUCED = "structural_predicate_not_reproduced"
    HUNTER_CONTRACT_MISMATCH = "hunter_contract_mismatch"


class VerificationEvidenceReference(BaseModel):
    """Hash-only evidence references carried across the verifier boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hunter_result_sha256: str
    perception_plan_sha256: str
    perception_evidence_sha256: str
    graph_sha256: str
    hypothesis_sha256: str
    verification_intent_sha256: str
    target_reference_sha256: str
    hypothesis_id: str
    intent_id: str
    target_node_id: str
    node_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    edge_ids: tuple[str, ...] = Field(default=(), max_length=64)
    evidence_grade: Literal["passive_structure_only"] = "passive_structure_only"

    @field_validator(
        "hunter_result_sha256",
        "perception_plan_sha256",
        "perception_evidence_sha256",
        "graph_sha256",
        "hypothesis_sha256",
        "verification_intent_sha256",
        "target_reference_sha256",
        "hypothesis_id",
        "intent_id",
        "target_node_id",
    )
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verification evidence identities must be SHA-256 digests")
        return value

    @field_validator("node_ids", "edge_ids")
    @classmethod
    def validate_reference_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("verification graph references must be SHA-256 digests")
        if len(values) != len(set(values)):
            raise ValueError("verification graph references must be unique")
        return values


class IndependentVerificationResult(BaseModel):
    """One integrity-linked verdict with no network or execution authority."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    verification_id: str
    verifier_id: str
    hunter_id: str
    vulnerability_class: str
    strategy: VerificationStrategy
    verdict: VerificationVerdict
    reason: VerificationReason
    structural_predicate_reproduced: bool
    evidence: VerificationEvidenceReference
    started_at: datetime
    completed_at: datetime
    network_access_performed: Literal[False] = False
    mutating_request_performed: Literal[False] = False
    credential_use_performed: Literal[False] = False
    authorization_bypass_performed: Literal[False] = False
    shell_execution_performed: Literal[False] = False
    external_evidence_accepted: Literal[False] = False
    result_sha256: str

    @field_validator("verification_id", "result_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verification result identities must be SHA-256 digests")
        return value

    @field_validator("verifier_id", "hunter_id", "vulnerability_class")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("verification identifiers must be stable lowercase values")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verification timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_result(self):
        if self.schema_version != 1:
            raise ValueError("independent verification schema is unsupported")
        if self.completed_at < self.started_at:
            raise ValueError("verification cannot complete before it starts")
        if self.verdict is VerificationVerdict.VALIDATED:
            raise ValueError("passive verifier foundation cannot validate vulnerability hypotheses")
        expected_verification_id = verification_id_for(
            verifier_id=self.verifier_id,
            hunter_result_sha256=self.evidence.hunter_result_sha256,
            hypothesis_id=self.evidence.hypothesis_id,
            intent_id=self.evidence.intent_id,
        )
        if self.verification_id != expected_verification_id:
            raise ValueError("verification ID does not match its bound source identities")
        if self.reason is VerificationReason.PASSIVE_EVIDENCE_INSUFFICIENT:
            if self.verdict is not VerificationVerdict.INCONCLUSIVE:
                raise ValueError("insufficient passive evidence must remain inconclusive")
            if not self.structural_predicate_reproduced:
                raise ValueError("inconclusive structural evidence must reproduce the predicate")
        elif self.reason is VerificationReason.STRUCTURAL_PREDICATE_NOT_REPRODUCED:
            if self.verdict is not VerificationVerdict.REJECTED:
                raise ValueError("a missing structural predicate must reject the hypothesis")
            if self.structural_predicate_reproduced:
                raise ValueError("a rejected structural predicate cannot be marked reproduced")
        elif self.reason is VerificationReason.HUNTER_CONTRACT_MISMATCH:
            if self.verdict is not VerificationVerdict.REJECTED:
                raise ValueError("a hunter contract mismatch must reject the hypothesis")
            if self.structural_predicate_reproduced:
                raise ValueError("contract mismatch cannot claim predicate reproduction")

        expected = sha256_json(self.model_dump(mode="json", exclude={"result_sha256"}))
        if expected != self.result_sha256:
            raise ValueError("verification result integrity hash does not match its contents")
        return self


class VerificationBatchResult(BaseModel):
    """One deterministic verifier pass over one exact hunter result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    batch_id: str
    verifier_id: str
    hunter_result_sha256: str
    target_reference_sha256: str
    started_at: datetime
    completed_at: datetime
    results: tuple[IndependentVerificationResult, ...] = Field(min_length=1, max_length=500)
    batch_sha256: str

    @field_validator(
        "batch_id",
        "hunter_result_sha256",
        "target_reference_sha256",
        "batch_sha256",
    )
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verification batch identities must be SHA-256 digests")
        return value

    @field_validator("verifier_id")
    @classmethod
    def validate_verifier_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("verifier_id must be a stable lowercase identifier")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verification timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_batch(self):
        if self.schema_version != 1:
            raise ValueError("verification batch schema is unsupported")
        if self.completed_at < self.started_at:
            raise ValueError("verification batch cannot complete before it starts")
        hypothesis_ids = [item.evidence.hypothesis_id for item in self.results]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("verification batch hypothesis IDs must be unique")
        if hypothesis_ids != sorted(hypothesis_ids):
            raise ValueError("verification batch results must use canonical hypothesis order")
        expected_batch_id = verification_batch_id_for(
            verifier_id=self.verifier_id,
            hunter_result_sha256=self.hunter_result_sha256,
            hypothesis_ids=tuple(hypothesis_ids),
        )
        if self.batch_id != expected_batch_id:
            raise ValueError("verification batch ID does not match its bound source identities")
        if any(item.verifier_id != self.verifier_id for item in self.results):
            raise ValueError("verification results must use the batch verifier identity")
        if any(
            item.evidence.hunter_result_sha256 != self.hunter_result_sha256 for item in self.results
        ):
            raise ValueError("verification results must bind the exact hunter result")
        if any(
            item.evidence.target_reference_sha256 != self.target_reference_sha256
            for item in self.results
        ):
            raise ValueError("verification results must bind the exact target reference")
        expected = sha256_json(self.model_dump(mode="json", exclude={"batch_sha256"}))
        if expected != self.batch_sha256:
            raise ValueError("verification batch integrity hash does not match its contents")
        return self


def verification_id_for(
    *,
    verifier_id: str,
    hunter_result_sha256: str,
    hypothesis_id: str,
    intent_id: str,
) -> str:
    return sha256_json(
        {
            "verifier_id": verifier_id,
            "hunter_result_sha256": hunter_result_sha256,
            "hypothesis_id": hypothesis_id,
            "intent_id": intent_id,
        }
    )


def verification_batch_id_for(
    *,
    verifier_id: str,
    hunter_result_sha256: str,
    hypothesis_ids: tuple[str, ...],
) -> str:
    return sha256_json(
        {
            "verifier_id": verifier_id,
            "hunter_result_sha256": hunter_result_sha256,
            "hypothesis_ids": list(hypothesis_ids),
        }
    )
