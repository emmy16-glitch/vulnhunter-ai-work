"""Typed, revisioned task-graph models for bounded multi-agent work."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class NodeStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    WAITING_FOR_HUMAN_APPROVAL = "waiting_for_human_approval"
    PAUSED = "paused"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


TERMINAL_STATUSES = frozenset(
    {
        NodeStatus.BLOCKED,
        NodeStatus.FAILED,
        NodeStatus.COMPLETED,
        NodeStatus.CANCELLED,
    }
)

_ALLOWED_TRANSITIONS: dict[NodeStatus, frozenset[NodeStatus]] = {
    NodeStatus.PENDING: frozenset(
        {
            NodeStatus.PENDING,
            NodeStatus.READY,
            NodeStatus.RUNNING,
            NodeStatus.BLOCKED,
            NodeStatus.CANCELLED,
        }
    ),
    NodeStatus.READY: frozenset(
        {NodeStatus.READY, NodeStatus.RUNNING, NodeStatus.PAUSED, NodeStatus.CANCELLED}
    ),
    NodeStatus.RUNNING: frozenset(
        {
            NodeStatus.RUNNING,
            NodeStatus.READY,
            NodeStatus.WAITING_FOR_HUMAN_APPROVAL,
            NodeStatus.PAUSED,
            NodeStatus.BLOCKED,
            NodeStatus.FAILED,
            NodeStatus.COMPLETED,
            NodeStatus.CANCELLED,
        }
    ),
    NodeStatus.WAITING_FOR_HUMAN_APPROVAL: frozenset(
        {
            NodeStatus.WAITING_FOR_HUMAN_APPROVAL,
            NodeStatus.RUNNING,
            NodeStatus.PAUSED,
            NodeStatus.CANCELLED,
        }
    ),
    NodeStatus.PAUSED: frozenset(
        {NodeStatus.PAUSED, NodeStatus.READY, NodeStatus.RUNNING, NodeStatus.CANCELLED}
    ),
    NodeStatus.BLOCKED: frozenset(),
    NodeStatus.FAILED: frozenset(),
    NodeStatus.COMPLETED: frozenset(),
    NodeStatus.CANCELLED: frozenset(),
}


class WorkerLease(BaseModel):
    """Short-lived, task-bound worker claim; it never grants authorization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    owner_id: str
    token_sha256: str
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime
    renewal_count: int = Field(default=0, ge=0, le=10_000)
    maximum_renewals: int = Field(default=100, ge=0, le=10_000)

    @field_validator("owner_id")
    @classmethod
    def validate_owner(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("lease owner must be a stable lowercase identifier")
        return value

    @field_validator("token_sha256")
    @classmethod
    def validate_token(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("lease token must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        if self.heartbeat_at < self.acquired_at:
            raise ValueError("lease heartbeat cannot predate acquisition")
        if self.expires_at <= self.heartbeat_at:
            raise ValueError("lease expiry must be later than heartbeat")
        if self.renewal_count > self.maximum_renewals:
            raise ValueError("lease renewal limit exceeded")
        return self

    def is_expired(self, *, now: datetime) -> bool:
        return now >= self.expires_at


class GraphNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    role_id: str
    skill_id: str
    action_manifest_sha256: str
    dependencies: tuple[str, ...] = ()
    status: NodeStatus = NodeStatus.PENDING
    attempts: int = Field(default=0, ge=0, le=100)
    maximum_attempts: int = Field(default=1, ge=1, le=100)
    last_error: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)
    lease: WorkerLease | None = None

    @field_validator("node_id", "role_id", "skill_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("action_manifest_sha256")
    @classmethod
    def validate_manifest_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("action_manifest_sha256 must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_lease_state(self) -> Self:
        if self.lease is not None and self.status != NodeStatus.RUNNING:
            raise ValueError("only running nodes may hold a worker lease")
        return self

    def validate_update_from(self, previous: GraphNode) -> None:
        immutable = (
            "node_id",
            "role_id",
            "skill_id",
            "action_manifest_sha256",
            "dependencies",
            "maximum_attempts",
        )
        for field_name in immutable:
            if getattr(self, field_name) != getattr(previous, field_name):
                raise ValueError(f"task node field is immutable: {field_name}")
        if self.status not in _ALLOWED_TRANSITIONS[previous.status]:
            raise ValueError(f"invalid node transition: {previous.status} -> {self.status}")
        if self.attempts < previous.attempts:
            raise ValueError("node attempts cannot decrease")
        if self.attempts > self.maximum_attempts:
            raise ValueError("node attempt limit exceeded")
        if self.updated_at < previous.updated_at:
            raise ValueError("node updated_at cannot move backwards")
        if previous.status in TERMINAL_STATUSES and self != previous:
            raise ValueError("terminal task nodes are immutable")
        if previous.lease is not None and self.lease is not None:
            if self.lease.owner_id != previous.lease.owner_id:
                raise ValueError("active lease owner is immutable")
            if self.lease.token_sha256 != previous.lease.token_sha256:
                raise ValueError("active lease token is immutable")
            if self.lease.acquired_at != previous.lease.acquired_at:
                raise ValueError("active lease acquisition time is immutable")
            if self.lease.heartbeat_at < previous.lease.heartbeat_at:
                raise ValueError("lease heartbeat cannot move backwards")
            if self.lease.expires_at < previous.lease.expires_at:
                raise ValueError("lease expiry cannot move backwards")
            if self.lease.renewal_count < previous.lease.renewal_count:
                raise ValueError("lease renewal count cannot decrease")


class TaskGraph(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "2.0"
    graph_id: str
    campaign_id: str
    run_id: str
    nodes: tuple[GraphNode, ...] = Field(min_length=1)
    revision: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("graph_id", "campaign_id", "run_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        node_ids = {node.node_id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("node identifiers must be unique")
        for node in self.nodes:
            if node.node_id in node.dependencies:
                raise ValueError("a node cannot depend on itself")
            unknown = set(node.dependencies) - node_ids
            if unknown:
                raise ValueError(f"node depends on unknown nodes: {sorted(unknown)}")
        self._assert_acyclic()
        if self.updated_at < self.created_at:
            raise ValueError("graph updated_at cannot predate creation")
        return self

    def _assert_acyclic(self) -> None:
        dependencies = {node.node_id: set(node.dependencies) for node in self.nodes}
        remaining = set(dependencies)
        while remaining:
            ready = {node_id for node_id in remaining if not (dependencies[node_id] & remaining)}
            if not ready:
                raise ValueError("task graph contains a dependency cycle")
            remaining -= ready

    def validate_update_from(self, previous: TaskGraph) -> None:
        for field_name in ("schema_version", "graph_id", "campaign_id", "run_id", "created_at"):
            if getattr(self, field_name) != getattr(previous, field_name):
                raise ValueError(f"task graph field is immutable: {field_name}")
        if self.revision != previous.revision + 1:
            raise ValueError("task graph revision must increase by exactly one")
        if self.updated_at < previous.updated_at:
            raise ValueError("task graph updated_at cannot move backwards")
        previous_by_id = {node.node_id: node for node in previous.nodes}
        current_by_id = {node.node_id: node for node in self.nodes}
        if current_by_id.keys() != previous_by_id.keys():
            raise ValueError(
                "task graph nodes cannot be added, removed, or replaced after creation"
            )
        for node_id, node in current_by_id.items():
            node.validate_update_from(previous_by_id[node_id])

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))
