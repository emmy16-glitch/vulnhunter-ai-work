"""Immutable contracts for bounded unattended operations."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ACTOR_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,95}$")
_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")


class ExecutionMode(StrEnum):
    """Supported scheduling and supervision modes."""

    INTERACTIVE_GOAL = "interactive_goal"
    SESSION = "session"
    LOCAL_SCHEDULED = "local_scheduled"
    CI_WORKFLOW = "ci_workflow"
    REMOTE_ROUTINE = "remote_routine"


class ToolCapability(StrEnum):
    """Runtime capabilities that must be explicitly granted."""

    REPOSITORY_READ = "repository_read"
    REPOSITORY_WRITE = "repository_write"
    COMMAND_RUNNER = "command_runner"
    CONNECTOR_READ = "connector_read"
    CONNECTOR_WRITE = "connector_write"
    SECRET_READ = "secret_read"
    NETWORK_CLIENT = "network_client"
    GIT_COMMIT = "git_commit"


class NetworkAccess(StrEnum):
    """Maximum network class available to a run."""

    NONE = "none"
    LOOPBACK = "loopback"
    PRIVATE_LAB = "private_lab"
    ALLOWLISTED_PUBLIC = "allowlisted_public"


class CommandId(StrEnum):
    """Shell-free commands in the trusted command registry."""

    GIT_STATUS = "git_status"
    GIT_DIFF_CHECK = "git_diff_check"
    RUFF_CHECK = "ruff_check"
    RUFF_FORMAT_CHECK = "ruff_format_check"
    COMPILE = "compile"
    PYTEST = "pytest"
    PROJECT_AUDIT = "project_audit"


class ActionKind(StrEnum):
    """Runtime actions checked by the permission enforcer."""

    READ_PATH = "read_path"
    WRITE_PATH = "write_path"
    DELETE_PATH = "delete_path"
    TOOL = "tool"
    COMMAND = "command"
    NETWORK = "network"
    CONNECTOR = "connector"
    SECRET = "secret"
    GIT_PUSH = "git_push"
    DEPLOY = "deploy"


class RunState(StrEnum):
    """Lifecycle of one unattended execution run."""

    RUNNING = "running"
    BLOCKED = "blocked"
    HALTED = "halted"
    COMPLETED = "completed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class BlockerClass(StrEnum):
    """Failure classes used by blocker isolation."""

    LOCAL_RECOVERABLE = "local_recoverable"
    DEPENDENCY = "dependency"
    PERMISSION = "permission"
    ENVIRONMENT = "environment"
    SECURITY_INVARIANT = "security_invariant"
    AUTHORIZATION = "authorization"
    SCOPE = "scope"
    DATA_INTEGRITY = "data_integrity"
    EVALUATOR = "evaluator"
    REQUIRED_VERIFIER = "required_verifier"
    UNKNOWN = "unknown"

    @property
    def halts_workflow(self) -> bool:
        """Return whether this blocker must halt the complete workflow."""
        return self in {
            BlockerClass.SECURITY_INVARIANT,
            BlockerClass.AUTHORIZATION,
            BlockerClass.SCOPE,
            BlockerClass.DATA_INTEGRITY,
            BlockerClass.EVALUATOR,
            BlockerClass.REQUIRED_VERIFIER,
        }


class SensitiveRemoteApproval(BaseModel):
    """Exceptional approval for protected data in a remote routine."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approved_by: str
    approved_at: datetime
    expires_at: datetime
    rationale: str = Field(min_length=20, max_length=1_000)
    data_classes: tuple[str, ...] = Field(min_length=1, max_length=20)
    encrypted_at_rest: bool
    encrypted_in_transit: bool
    isolated_runtime: bool
    data_minimization: bool

    @field_validator("approved_by")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        return normalize_actor_id(value)

    @field_validator("data_classes", mode="before")
    @classmethod
    def normalize_classes(cls, value):
        items = tuple(str(item).strip().lower() for item in value)
        if any(not _NAME_PATTERN.fullmatch(item) for item in items):
            raise ValueError("Data classes must be stable lowercase identifiers.")
        if len(items) != len(set(items)):
            raise ValueError("Data classes must be unique.")
        return items

    @model_validator(mode="after")
    def validate_controls(self):
        if self.expires_at <= self.approved_at:
            raise ValueError("Sensitive remote approval must expire after approval.")
        if not all(
            (
                self.encrypted_at_rest,
                self.encrypted_in_transit,
                self.isolated_runtime,
                self.data_minimization,
            )
        ):
            raise ValueError("Every technical protection control must be enabled.")
        return self


class PermissionManifest(BaseModel):
    """Runtime-enforced permission boundary for one loop."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    manifest_id: str
    loop_id: str
    repository_root: Path
    execution_mode: ExecutionMode
    available_tools: tuple[ToolCapability, ...]
    approved_read_paths: tuple[str, ...] = ()
    approved_write_paths: tuple[str, ...] = ()
    approved_commands: tuple[CommandId, ...] = ()
    required_completion_commands: tuple[CommandId, ...] = ()
    network_access: NetworkAccess = NetworkAccess.NONE
    approved_network_hosts: tuple[str, ...] = ()
    target_authorization_ids: tuple[str, ...] = ()
    approved_connectors: tuple[str, ...] = ()
    approved_secret_names: tuple[str, ...] = ()
    allow_git_push: bool = False
    allow_delete: bool = False
    allow_deploy: bool = False
    maximum_runtime_seconds: int = Field(default=3_600, ge=60, le=86_400)
    maximum_iterations: int = Field(default=25, ge=1, le=1_000)
    maximum_repeated_failures: int = Field(default=2, ge=2, le=2)
    independent_task_ids: tuple[str, ...] = ()
    created_by: str
    created_at: datetime
    expires_at: datetime
    remote_sensitive_approval: SensitiveRemoteApproval | None = None

    @field_validator("manifest_id", "loop_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _ID_PATTERN.fullmatch(normalized):
            raise ValueError("Identifiers must be stable lowercase values.")
        return normalized

    @field_validator("created_by")
    @classmethod
    def validate_creator(cls, value: str) -> str:
        return normalize_actor_id(value)

    @field_validator(
        "available_tools",
        "approved_commands",
        "required_completion_commands",
    )
    @classmethod
    def unique_enums(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("Permission lists must not contain duplicates.")
        return value

    @field_validator(
        "approved_read_paths",
        "approved_write_paths",
        mode="before",
    )
    @classmethod
    def normalize_paths(cls, value):
        items = tuple(str(item).strip().replace("\\", "/") for item in value)
        for item in items:
            path = PurePosixPath(item)
            if not item or path.is_absolute() or ".." in path.parts:
                raise ValueError("Approved paths must be repository-relative and traversal-free.")
        if len(items) != len(set(items)):
            raise ValueError("Approved paths must be unique.")
        return items

    @field_validator(
        "approved_network_hosts",
        "approved_connectors",
        "approved_secret_names",
        "target_authorization_ids",
        "independent_task_ids",
        mode="before",
    )
    @classmethod
    def normalize_names(cls, value):
        items = tuple(str(item).strip().lower() for item in value)
        if any(not _ID_PATTERN.fullmatch(item) for item in items):
            raise ValueError("Permission names must be stable lowercase identifiers.")
        if len(items) != len(set(items)):
            raise ValueError("Permission names must be unique.")
        return items

    @model_validator(mode="after")
    def validate_policy(self):
        if self.expires_at <= self.created_at:
            raise ValueError("Permission manifest must expire after creation.")
        if self.required_completion_commands and not set(
            self.required_completion_commands
        ).issubset(self.approved_commands):
            raise ValueError("Completion commands must also be approved commands.")
        if self.approved_commands and ToolCapability.COMMAND_RUNNER not in self.available_tools:
            raise ValueError("Approved commands require the command_runner tool.")
        if (
            self.approved_write_paths
            and ToolCapability.REPOSITORY_WRITE not in self.available_tools
        ):
            raise ValueError("Write paths require repository_write capability.")
        if self.approved_secret_names and ToolCapability.SECRET_READ not in self.available_tools:
            raise ValueError("Secret names require secret_read capability.")
        if self.approved_connectors and not {
            ToolCapability.CONNECTOR_READ,
            ToolCapability.CONNECTOR_WRITE,
        }.intersection(self.available_tools):
            raise ValueError("Connector access requires a connector capability.")
        if (
            self.network_access != NetworkAccess.NONE
            and ToolCapability.NETWORK_CLIENT not in self.available_tools
        ):
            raise ValueError("Network access requires network_client capability.")
        if self.network_access == NetworkAccess.PRIVATE_LAB and not self.target_authorization_ids:
            raise ValueError("Private-lab network access requires target authorization IDs.")
        if (
            self.network_access == NetworkAccess.ALLOWLISTED_PUBLIC
            and not self.approved_network_hosts
        ):
            raise ValueError("Public network access requires an exact host allowlist.")
        if self.execution_mode == ExecutionMode.REMOTE_ROUTINE:
            if self.allow_git_push or self.allow_delete or self.allow_deploy:
                raise ValueError("Remote routines cannot push, delete, or deploy.")
            if self.maximum_iterations > 20 or len(self.approved_write_paths) > 5:
                raise ValueError("Remote routines must remain narrowly scoped.")
            if len(self.approved_connectors) > 1:
                raise ValueError("Remote routines may use at most one connector.")
            if self.approved_secret_names and self.remote_sensitive_approval is None:
                raise ValueError("Remote secret access requires protected sensitive-data approval.")
        return self


class ApprovalRecord(BaseModel):
    """Human approval bound to one immutable manifest hash."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str
    manifest_sha256: str = Field(min_length=64, max_length=64)
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    reason: str = Field(min_length=10, max_length=1_000)

    @field_validator("approved_by")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        return normalize_actor_id(value)

    @model_validator(mode="after")
    def validate_expiry(self):
        if self.expires_at <= self.approved_at:
            raise ValueError("Approval must expire after it is granted.")
        return self


class TaskProfile(BaseModel):
    """Inputs to the scheduling decision matrix."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    requires_supervision: bool = False
    temporary_repetition: bool = False
    deterministic_checks_only: bool = False
    private_repository_work: bool = True
    remote_execution_required: bool = False
    contains_sensitive_security_data: bool = False
    needs_connectors: bool = False
    needs_network: bool = False
    needs_write: bool = False
    expected_duration_minutes: int = Field(default=30, ge=1, le=10_080)


class ScheduleRecommendation(BaseModel):
    """Non-executable scheduling recommendation and safeguards."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: ExecutionMode | None
    permitted: bool
    rationale: tuple[str, ...]
    required_controls: tuple[str, ...]


class PermissionDecision(BaseModel):
    """One runtime permission decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: ActionKind
    value: str
    allowed: bool
    rationale: str
    checked_at: datetime


class CommandEvidence(BaseModel):
    """Redacted evidence from a trusted fixed command."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    command_id: CommandId
    actor_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    evidence_sha256: str = Field(min_length=64, max_length=64)


class FailureRecord(BaseModel):
    """Material failure fingerprint used for blocker isolation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    item_id: str
    operation: str
    error_code: str
    summary: str
    blocker_class: BlockerClass
    fingerprint: str = Field(min_length=64, max_length=64)
    occurrence: int = Field(ge=1)
    isolated: bool
    workflow_halted: bool
    recorded_at: datetime


class RunRecord(BaseModel):
    """Persistent state for one approved unattended run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    manifest_id: str
    manifest_sha256: str = Field(min_length=64, max_length=64)
    repository_commit: str
    state: RunState
    started_by: str
    started_at: datetime
    updated_at: datetime
    iterations_used: int = Field(default=0, ge=0)
    isolated_item_ids: tuple[str, ...] = ()
    completed_task_ids: tuple[str, ...] = ()
    last_error: str | None = None

    @field_validator("started_by")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        return normalize_actor_id(value)


class AuditEvent(BaseModel):
    """One hash-chained control-plane event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=1)
    subject_id: str
    event_type: str
    actor_id: str
    created_at: datetime
    payload: dict[str, object]
    previous_hash: str = Field(min_length=64, max_length=64)
    event_hash: str = Field(min_length=64, max_length=64)


def normalize_actor_id(value: str) -> str:
    """Normalize a pseudonymous human or service actor identifier."""
    normalized = value.strip().lower()
    if not _ACTOR_PATTERN.fullmatch(normalized):
        raise ValueError("Actor IDs must be stable lowercase pseudonyms.")
    return normalized
