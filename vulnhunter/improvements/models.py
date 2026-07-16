"""Governed self-improvement proposal models."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ImprovementRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SECURITY_CRITICAL = "security_critical"


class ProposalStatus(StrEnum):
    PROPOSED = "proposed"
    TESTS_REQUIRED = "tests_required"
    INDEPENDENT_VERIFICATION_REQUIRED = "independent_verification_required"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    APPROVED_FOR_MANUAL_DEPLOYMENT = "approved_for_manual_deployment"
    REJECTED = "rejected"


class ImprovementProposal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str
    component: str
    risk: ImprovementRisk
    affected_files: tuple[str, ...] = Field(min_length=1)
    rationale: str = Field(min_length=8, max_length=1_000)
    tests: tuple[str, ...] = ()
    independent_verification_sha256: str | None = None
    rollback_plan: str = Field(min_length=8, max_length=1_000)
    status: ProposalStatus = ProposalStatus.PROPOSED
    activates_production_configuration: bool = False

    @field_validator("proposal_id", "component")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("independent_verification_sha256")
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("independent verification must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_no_auto_activation(self) -> Self:
        if self.activates_production_configuration:
            raise ValueError(
                "improvement proposals cannot directly activate production configuration"
            )
        if self.status == ProposalStatus.APPROVED_FOR_MANUAL_DEPLOYMENT:
            if not self.tests or not self.independent_verification_sha256:
                raise ValueError("approved proposals require tests and independent verification")
        return self
