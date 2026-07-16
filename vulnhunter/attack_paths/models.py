"""Attack-path graph models with truthful verification state."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AttackPathState(StrEnum):
    HYPOTHETICAL = "hypothetical"
    PARTIAL = "partial"
    CONFIRMED = "confirmed"


class AttackPathNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    node_type: str
    label: str = Field(min_length=1, max_length=200)
    evidence_sha256: str | None = None
    oracle_session_id: str | None = None

    @field_validator("node_id", "node_type", "oracle_session_id")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("evidence_sha256")
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("evidence_sha256 must be a SHA-256 digest")
        return value


class AttackPathStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    from_node: str
    to_node: str
    precondition: str
    weakness: str
    permission: str | None = None
    confidence: str
    verified: bool = False

    @field_validator("from_node", "to_node")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value


class AttackPath(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path_id: str
    campaign_id: str
    target_reference: str
    nodes: tuple[AttackPathNode, ...] = Field(min_length=2)
    steps: tuple[AttackPathStep, ...] = Field(min_length=1)
    state: AttackPathState
    remediation_controls: tuple[str, ...] = ()

    @field_validator("path_id", "campaign_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        node_ids = {node.node_id for node in self.nodes}
        for step in self.steps:
            if step.from_node not in node_ids or step.to_node not in node_ids:
                raise ValueError("attack-path step references an unknown node")
        all_verified = all(step.verified for step in self.steps)
        if self.state == AttackPathState.CONFIRMED and not all_verified:
            raise ValueError("confirmed attack paths require every step to be verified")
        if self.state == AttackPathState.HYPOTHETICAL and all_verified:
            raise ValueError("fully verified paths must not be labelled hypothetical")
        return self
