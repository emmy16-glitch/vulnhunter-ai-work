"""Bounded context-broker contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class ContextConfidence(StrEnum):
    VERIFIED = "verified"
    EXTRACTED = "extracted"
    INFERRED = "inferred"
    AMBIGUOUS = "ambiguous"


class ContextFreshness(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    UNKNOWN = "unknown"


class ContextSourceKind(StrEnum):
    FILE_EXCERPT = "file_excerpt"
    GRAPH_NODE = "graph_node"
    GRAPH_EDGE = "graph_edge"
    TASK_HISTORY = "task_history"
    RULE = "rule"
    AUTHORIZATION = "authorization"
    CONTRADICTION = "contradiction"
    EMBEDDING = "embedding"


class ContextQuery(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    query_id: str
    text: str = Field(min_length=2, max_length=2_000)
    allowed_paths: tuple[str, ...] = ()
    authorization_references: tuple[str, ...] = ()
    maximum_items: int = Field(default=30, ge=1, le=500)
    maximum_excerpt_characters: int = Field(default=2_000, ge=100, le=20_000)
    maximum_graph_nodes: int = Field(default=20, ge=1, le=200)
    maximum_graph_edges: int = Field(default=40, ge=1, le=500)
    maximum_scanned_files: int = Field(default=200, ge=1, le=2_000)
    maximum_scanned_bytes: int = Field(default=2_000_000, ge=1_024, le=20_000_000)
    maximum_bundle_bytes: int = Field(default=64_000, ge=1_024, le=1_000_000)
    include_task_history: bool = True
    include_graph: bool = True
    allow_embedding_retrieval: bool = False

    @field_validator("query_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("query_id must be a stable lowercase identifier")
        return value

    @field_validator("allowed_paths")
    @classmethod
    def validate_allowed_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            path = PurePosixPath(value.replace("\\", "/").strip("/"))
            if not path.parts or path.is_absolute() or ".." in path.parts:
                raise ValueError("allowed paths must be repository-relative")
            name = path.name.lower()
            if name == ".env" or name.startswith(".env.") or name == "agent.db":
                raise ValueError("allowed paths may not select secret or runtime files")
            normalized.append(path.as_posix())
        return tuple(dict.fromkeys(normalized))


class ContextItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_kind: ContextSourceKind
    source_id: str
    path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    content: str = Field(min_length=1, max_length=20_000)
    confidence: ContextConfidence
    freshness: ContextFreshness
    source_sha256: str | None = None
    metadata: dict[str, str | int | bool] = Field(default_factory=dict)


class ContextBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    query_id: str
    items: tuple[ContextItem, ...]
    relevant_files: tuple[str, ...]
    relevant_symbols: tuple[str, ...]
    contradictions: tuple[str, ...]
    task_specific_rules: tuple[str, ...]
    authorization_references: tuple[str, ...]
    repository_state_sha256: str | None = None
    graph_status: str = "unavailable"
    graph_fallback_reason: str | None = None
    selected_graph_nodes: tuple[str, ...] = ()
    selected_graph_edges: tuple[str, ...] = ()
    content_bytes: int = Field(default=0, ge=0)
    truncated: bool = False
    created_at: datetime = Field(default_factory=utc_now)
