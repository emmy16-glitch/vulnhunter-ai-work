"""Bounded remote-advisory provider contracts that never embed credentials."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class ProviderKind(StrEnum):
    GROQ_ADVISORY = "groq_advisory"
    HUGGINGFACE_ADVISORY = "huggingface_advisory"


class ProviderRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    purpose: str = Field(min_length=8, max_length=500)
    content: str = Field(min_length=1, max_length=200_000)
    allow_current_public_information: bool = False
    contains_private_source: bool = False
    contains_customer_data: bool = False
    remote_source_processing_approved: bool = False

    @field_validator("request_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("request_id must be a stable lowercase identifier")
        return value

    @model_validator(mode="after")
    def private_source_requires_explicit_approval(self):
        if self.remote_source_processing_approved and not self.contains_private_source:
            raise ValueError("remote source approval is valid only for a private-source request")
        return self


class ProviderRoute(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: ProviderKind
    allowed: bool
    reason: str
    redacted_content: str | None = None


class ProviderCapability(StrEnum):
    SUMMARIZATION = "summarization"
    CLASSIFICATION = "classification"
    REMEDIATION_DRAFTING = "remediation_drafting"
    REPOSITORY_NAVIGATION = "repository_navigation"
    PUBLIC_INFORMATION = "public_information"
    CONVERSATION = "conversation"
    SOURCE_RECONNAISSANCE = "source_reconnaissance"
    ATTACK_PATH_ANALYSIS = "attack_path_analysis"
    CANDIDATE_FALSIFICATION = "candidate_falsification"
    CAPABILITY_ASSESSMENT = "capability_assessment"
    REMEDIATION_PLANNING = "remediation_planning"
    FIX_REVIEW = "fix_review"


class ProviderHealth(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: ProviderKind
    configured: bool
    reachable: bool
    reason: str
    model: str | None = None
    model_digest: str | None = None
    provider_version: str | None = None
    endpoint_classification: str | None = None


class ProviderInvocation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    invocation_id: str
    request_id: str
    provider: ProviderKind
    model: str
    capability: ProviderCapability
    input_sha256: str
    maximum_input_characters: int = Field(default=24_000, ge=1, le=100_000)
    maximum_output_characters: int = Field(default=8_000, ge=1, le=40_000)
    maximum_input_bytes: int = Field(default=24_000, ge=1, le=100_000)
    maximum_output_bytes: int = Field(default=8_000, ge=1, le=40_000)
    maximum_input_tokens: int = Field(default=6_000, ge=1, le=25_000)
    maximum_output_tokens: int = Field(default=1_200, ge=1, le=8_192)
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    reasoning_effort: Literal["low", "medium", "high"] = "high"

    @field_validator("invocation_id", "request_id")
    @classmethod
    def validate_invocation_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be stable and lowercase")
        return value

    @field_validator("input_sha256")
    @classmethod
    def validate_input_sha(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("input_sha256 must be a SHA-256 digest")
        return value


class ProviderOutputKind(StrEnum):
    PROPOSAL = "PROPOSAL"
    CANDIDATE_ANALYSIS = "CANDIDATE_ANALYSIS"
    ABSTAIN = "ABSTAIN"


class ProviderProvenance(BaseModel):
    """Bounded provider metadata; never contains the raw prompt or credential."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_name: str
    model_digest: str | None = None
    provider_version: str | None = None
    endpoint_classification: str
    prompt_template_version: str
    request_timestamp: datetime
    response_timestamp: datetime
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_bytes: int = Field(ge=0)
    output_bytes: int = Field(ge=0)
    timed_out: bool = False
    cancelled: bool = False


class ProviderResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    invocation_id: str
    provider: ProviderKind
    model: str
    content: str = Field(max_length=40_000)
    output_sha256: str
    output_kind: ProviderOutputKind = ProviderOutputKind.PROPOSAL
    trusted: bool = False
    degraded: bool = False
    safe_error: str | None = None
    provenance: ProviderProvenance | None = None

    @field_validator("output_sha256")
    @classmethod
    def validate_output_sha(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("output_sha256 must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def model_output_cannot_be_authoritative(self):
        if self.trusted:
            raise ValueError("provider output can never be marked trusted")
        return self
