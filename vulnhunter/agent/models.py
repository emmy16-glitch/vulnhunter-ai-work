"""Immutable data models for the bounded VulnHunter agent runtime."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import ActionManifest
from vulnhunter.approvals.conditions import CanonicalApprovalExecutionPlan

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)


def canonical_json(value: object) -> bytes:
    """Serialize JSON deterministically for fingerprints and audit evidence."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    """Return the SHA-256 of canonical JSON."""

    return hashlib.sha256(canonical_json(value)).hexdigest()


class TaskStatus(StrEnum):
    """Lifecycle states for one bounded agent task."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED_APPROVAL = "paused_approval"
    PAUSED_BUDGET = "paused_budget"
    PAUSED_OPERATOR = "paused_operator"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


_ALLOWED_TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.CREATED: frozenset(
        {
            TaskStatus.CREATED,
            TaskStatus.RUNNING,
            TaskStatus.PAUSED_OPERATOR,
            TaskStatus.CANCELLED,
            TaskStatus.TIMED_OUT,
        }
    ),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.PAUSED_APPROVAL,
            TaskStatus.PAUSED_BUDGET,
            TaskStatus.PAUSED_OPERATOR,
            TaskStatus.BLOCKED,
            TaskStatus.FAILED,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.TIMED_OUT,
        }
    ),
    TaskStatus.PAUSED_APPROVAL: frozenset(
        {
            TaskStatus.PAUSED_APPROVAL,
            TaskStatus.RUNNING,
            TaskStatus.CANCELLED,
            TaskStatus.TIMED_OUT,
        }
    ),
    TaskStatus.PAUSED_BUDGET: frozenset(
        {
            TaskStatus.PAUSED_BUDGET,
            TaskStatus.RUNNING,
            TaskStatus.PAUSED_OPERATOR,
            TaskStatus.CANCELLED,
            TaskStatus.TIMED_OUT,
        }
    ),
    TaskStatus.PAUSED_OPERATOR: frozenset(
        {
            TaskStatus.PAUSED_OPERATOR,
            TaskStatus.RUNNING,
            TaskStatus.CANCELLED,
            TaskStatus.TIMED_OUT,
        }
    ),
    TaskStatus.BLOCKED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
    TaskStatus.TIMED_OUT: frozenset(),
}


class ProposalKind(StrEnum):
    """Kinds of planner proposals."""

    TOOL = "tool"
    COMPLETE = "complete"
    PAUSE = "pause"


class PolicyStatus(StrEnum):
    """Result of deterministic policy evaluation."""

    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


class EvaluationStatus(StrEnum):
    """Result of evaluating an executed tool call."""

    CONTINUE = "continue"
    RETRY = "retry"
    FAIL = "fail"


class ToolRisk(StrEnum):
    """Side-effect and privilege classes for tools."""

    READ_ONLY = "read_only"
    LOCAL_WRITE = "local_write"
    NETWORK = "network"
    CONNECTOR = "connector"
    SECRETS = "secrets"
    GIT_WRITE = "git_write"
    DEPLOYMENT = "deployment"


class RuntimeConfig(BaseModel):
    """Repository-controlled global runtime limits and denied capabilities."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    runtime_id: str = "vulnhunter-bounded-agent"
    max_controller_iterations: int = Field(default=25, ge=1, le=500)
    global_denied_actions: tuple[str, ...] = (
        "authorization.override",
        "connector.enable",
        "deployment.execute",
        "git.push",
        "review.self_approve",
        "secrets.read",
    )
    require_hash_chained_audit: Literal[True] = True
    connectors_enabled: Literal[False] = False
    unrestricted_shell_enabled: Literal[False] = False
    public_scanning_enabled: Literal[False] = False

    @field_validator("runtime_id")
    @classmethod
    def validate_runtime_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("runtime_id must be a stable lowercase identifier")
        return value


class PermissionManifest(BaseModel):
    """Per-task least-privilege limits enforced independently of the planner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str
    role_id: str
    skill_id: str | None = None
    allowed_actions: tuple[str, ...] = Field(min_length=1)
    allowed_tools: tuple[str, ...] = Field(min_length=1)
    allowed_risks: tuple[ToolRisk, ...] = (ToolRisk.READ_ONLY,)
    approval_required_actions: tuple[str, ...] = ()
    max_steps: int = Field(default=20, ge=1, le=500)
    max_tool_calls: int = Field(default=20, ge=1, le=500)
    max_identical_failures: int = Field(default=2, ge=1, le=10)
    maximum_runtime_seconds: int = Field(default=3_600, ge=1, le=86_400)
    allow_network: bool = False
    allow_connectors: bool = False
    allow_secrets: bool = False
    allow_git_write: bool = False
    allow_deployment: bool = False
    expires_at: datetime | None = None

    @field_validator("manifest_id", "role_id", "skill_id")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifiers must be stable lowercase values")
        return value

    @model_validator(mode="after")
    def validate_capability_flags(self) -> Self:
        risks = set(self.allowed_risks)
        requirements = {
            ToolRisk.NETWORK: self.allow_network,
            ToolRisk.CONNECTOR: self.allow_connectors,
            ToolRisk.SECRETS: self.allow_secrets,
            ToolRisk.GIT_WRITE: self.allow_git_write,
            ToolRisk.DEPLOYMENT: self.allow_deployment,
        }
        inconsistent = [
            risk.value for risk, flag in requirements.items() if risk in risks and not flag
        ]
        if inconsistent:
            raise ValueError(
                f"allowed_risks require matching explicit capability flags: {sorted(inconsistent)}"
            )
        if len(set(self.allowed_actions)) != len(self.allowed_actions):
            raise ValueError("allowed_actions must be unique")
        if len(set(self.allowed_tools)) != len(self.allowed_tools):
            raise ValueError("allowed_tools must be unique")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class AgentApprovalBinding(BaseModel):
    """Canonical Approval Centre inputs bound to one agent execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    execution_id: str
    consumer_actor_id: str
    action_manifest: ActionManifest
    execution_plan: CanonicalApprovalExecutionPlan

    @field_validator("request_id", "execution_id", "consumer_actor_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("approval binding identities must be stable lowercase values")
        return value

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        manifest_sha256 = self.action_manifest.fingerprint()
        if self.execution_plan.action_manifest_sha256 != manifest_sha256:
            raise ValueError("approval execution plan is bound to another manifest")
        if self.execution_plan.execution_id != self.execution_id:
            raise ValueError("approval execution plan is bound to another execution")
        return self


class ToolSpec(BaseModel):
    """Immutable declaration for one executable tool operation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: str
    action: str
    operation: str
    description: str = Field(min_length=8)
    risk: ToolRisk = ToolRisk.READ_ONLY
    retryable_errors: bool = False

    @field_validator("tool_id", "action", "operation")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("tool identifiers must be stable lowercase values")
        return value

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class ToolCall(BaseModel):
    """Planner-requested invocation validated before execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: str
    action: str
    operation: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_reference: str | None = None

    @field_validator("tool_id", "action", "operation")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("tool call identifiers must be stable lowercase values")
        return value

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class AgentProposal(BaseModel):
    """Strict structured output accepted from a deterministic or model planner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ProposalKind
    rationale: str = Field(min_length=3)
    call: ToolCall | None = None
    final_summary: str | None = None
    pause_reason: str | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.kind == ProposalKind.TOOL and self.call is None:
            raise ValueError("tool proposals require call")
        if self.kind != ProposalKind.TOOL and self.call is not None:
            raise ValueError("only tool proposals may include call")
        if self.kind == ProposalKind.COMPLETE and not self.final_summary:
            raise ValueError("complete proposals require final_summary")
        if self.kind == ProposalKind.PAUSE and not self.pause_reason:
            raise ValueError("pause proposals require pause_reason")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class PolicyDecision(BaseModel):
    """Deterministic authorization result for one planner proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: PolicyStatus
    reason: str
    proposal_sha256: str
    manifest_sha256: str
    tool_spec_sha256: str | None = None

    @field_validator("proposal_sha256", "manifest_sha256", "tool_spec_sha256")
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("hash values must be lowercase SHA-256 digests")
        return value


class ToolResult(BaseModel):
    """Normalized result of an approved tool execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    success: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error_type: str | None = None
    error_message: str | None = None
    retryable: bool = False
    call_sha256: str
    evidence_sha256: str

    @model_validator(mode="after")
    def validate_error_shape(self) -> Self:
        if self.success and (self.error_type or self.error_message or self.retryable):
            raise ValueError("successful tool results cannot contain error state")
        if not self.success and not self.error_message:
            raise ValueError("failed tool results require error_message")
        return self

    @field_validator("call_sha256", "evidence_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("hash values must be lowercase SHA-256 digests")
        return value


class EvaluationResult(BaseModel):
    """Controller decision after one tool result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: EvaluationStatus
    reason: str
    failure_fingerprint: str | None = None

    @field_validator("failure_fingerprint")
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("failure_fingerprint must be a SHA-256 digest")
        return value


class AgentTask(BaseModel):
    """Persisted resumable state for one objective."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    objective: str = Field(min_length=8)
    status: TaskStatus = TaskStatus.CREATED
    permission_manifest: PermissionManifest
    approval_binding: AgentApprovalBinding | None = None
    step_count: int = Field(default=0, ge=0)
    tool_call_count: int = Field(default=0, ge=0)
    revision: int = Field(default=0, ge=0)
    failure_counts: dict[str, int] = Field(default_factory=dict)
    memory: dict[str, Any] = Field(default_factory=dict)
    paused_reason: str | None = None
    final_summary: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    deadline_at: datetime | None = None

    @field_validator("task_id")
    @classmethod
    def validate_task_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("task_id must be a stable lowercase identifier")
        return value

    @field_validator("created_at", "updated_at", "deadline_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("task timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_deadline(self) -> Self:
        expected = self.created_at + timedelta(
            seconds=self.permission_manifest.maximum_runtime_seconds
        )
        if self.deadline_at is None:
            object.__setattr__(self, "deadline_at", expected)
        elif self.deadline_at != expected:
            raise ValueError("deadline_at must match the immutable task runtime budget")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        return self

    @property
    def terminal(self) -> bool:
        return self.status in {
            TaskStatus.BLOCKED,
            TaskStatus.FAILED,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.TIMED_OUT,
        }

    def evolved(self, **changes: Any) -> AgentTask:
        changes.setdefault("updated_at", utc_now())
        changes.setdefault("revision", self.revision + 1)
        candidate = AgentTask.model_validate(
            self.model_copy(update=changes).model_dump(mode="python")
        )
        candidate.validate_update_from(self)
        return candidate

    def validate_update_from(self, previous: AgentTask) -> None:
        """Validate one persisted state transition against its prior snapshot."""

        immutable_fields = (
            "task_id",
            "objective",
            "permission_manifest",
            "approval_binding",
            "created_at",
            "deadline_at",
        )
        changed = [
            field for field in immutable_fields if getattr(self, field) != getattr(previous, field)
        ]
        if changed:
            raise ValueError(f"immutable task fields changed: {changed}")
        if previous.terminal:
            raise ValueError("terminal agent tasks are immutable")
        if self.status not in _ALLOWED_TASK_TRANSITIONS[previous.status]:
            raise ValueError(
                f"invalid agent task transition: {previous.status.value} -> {self.status.value}"
            )
        if self.revision != previous.revision + 1:
            raise ValueError("task revision must increase by exactly one")
        if self.updated_at < previous.updated_at:
            raise ValueError("task updated_at cannot move backwards")
        if self.step_count < previous.step_count:
            raise ValueError("task step_count cannot decrease")
        if self.tool_call_count < previous.tool_call_count:
            raise ValueError("task tool_call_count cannot decrease")


class AuditEvent(BaseModel):
    """One immutable hash-chained runtime event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    sequence: int = Field(ge=1)
    event_type: str
    payload: dict[str, Any]
    created_at: datetime
    previous_sha256: str
    event_sha256: str

    @field_validator("previous_sha256", "event_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("audit hashes must be lowercase SHA-256 digests")
        return value


class ExecutionReport(BaseModel):
    """Deterministic summary of a task and its complete audit chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    status: TaskStatus
    objective: str
    step_count: int
    tool_call_count: int
    event_count: int
    final_event_sha256: str
    permission_manifest_sha256: str
    final_summary: str | None
    paused_reason: str | None
    report_sha256: str
