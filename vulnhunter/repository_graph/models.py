"""Native, provenance-rich repository graph contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:/#-]{1,511}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class GraphNodeKind(StrEnum):
    FILE = "file"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    ROUTE = "route"
    TEST = "test"
    DOCUMENT = "document"


class GraphEdgeKind(StrEnum):
    DEFINES = "defines"
    IMPORTS = "imports"
    CALLS = "calls"
    REFERENCES = "references"
    TESTS = "tests"
    ROUTES_TO = "routes_to"
    LINKS = "links"


class RelationshipConfidence(StrEnum):
    EXTRACTED = "extracted"
    INFERRED = "inferred"
    AMBIGUOUS = "ambiguous"


class RepositoryGraphNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    kind: GraphNodeKind
    name: str = Field(min_length=1, max_length=512)
    path: str
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    source_sha256: str
    metadata: dict[str, str | int | bool] = Field(default_factory=dict)

    @field_validator("node_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("graph node id is malformed")
        return value

    @field_validator("source_sha256")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("source_sha256 must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_lines(self):
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end cannot precede line_start")
        return self


class RepositoryGraphEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str
    target_id: str
    kind: GraphEdgeKind
    confidence: RelationshipConfidence
    provenance_path: str
    provenance_line: int | None = Field(default=None, ge=1)
    evidence: str = Field(min_length=1, max_length=1_000)


class RepositoryFileState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str
    size_bytes: int = Field(ge=0)

    @field_validator("sha256")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("sha256 must be a SHA-256 digest")
        return value


class RepositoryGraphSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    repository_root: str
    repository_state_sha256: str
    nodes: tuple[RepositoryGraphNode, ...]
    edges: tuple[RepositoryGraphEdge, ...]
    files: tuple[RepositoryFileState, ...]
    changed_files: tuple[str, ...] = ()
    removed_files: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("repository_state_sha256")
    @classmethod
    def validate_root_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("repository_state_sha256 must be a SHA-256 digest")
        return value


class GraphifyNode(BaseModel):
    """Small validated projection of an advisory Graphify node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str = Field(min_length=1, max_length=1_024)
    label: str = Field(min_length=1, max_length=1_024)
    source_file: str | None = Field(default=None, max_length=2_048)
    source_location: str | None = Field(default=None, max_length=128)
    confidence: RelationshipConfidence = RelationshipConfidence.EXTRACTED


class GraphifyEdge(BaseModel):
    """Small validated projection of an advisory Graphify relationship."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(min_length=1, max_length=1_024)
    target_id: str = Field(min_length=1, max_length=1_024)
    relation: str = Field(min_length=1, max_length=256)
    confidence: RelationshipConfidence = RelationshipConfidence.EXTRACTED


class GraphifyArtifact(BaseModel):
    """Accepted Graphify graph plus immutable repository provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_root: str
    repository_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    graph_path: str
    graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_bytes: int = Field(ge=2)
    graphify_version: str = Field(min_length=1, max_length=128)
    nodes: tuple[GraphifyNode, ...]
    edges: tuple[GraphifyEdge, ...]
    created_at: datetime = Field(default_factory=utc_now)
