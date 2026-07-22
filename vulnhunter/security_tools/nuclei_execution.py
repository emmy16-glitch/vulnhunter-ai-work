"""Controlled Nuclei execution harness with production execution disabled.

This module builds the manager/worker boundary, lifecycle, persistence, bounded
capture, cancellation, timeout, compatibility, and evidence contracts required
before a future isolated worker can exist.  It deliberately contains no real
subprocess launcher and no default network resolver.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.security import redact_mapping, redact_text
from vulnhunter.security_tools.nuclei_activation import (
    AddressResolver,
    EngagementAuthorization,
    NucleiActivationError,
    NucleiCancellationError,
    NucleiCommandPlan,
    NucleiPlanApproval,
    NucleiRunControl,
    NucleiTimeoutError,
    ProcessGroupTerminator,
    ScopedNucleiTarget,
    validate_evidence_directory,
    validate_nuclei_plan_approval,
    verify_redacted_evidence,
)
from vulnhunter.security_tools.scanner_protocol import (
    SCANNER_PROTOCOL_VERSION,
    ScannerAdapterDescriptor,
    ScannerAdapterResult,
    ScannerAdapterStatus,
    ScannerCandidateObservation,
    ScannerCompatibilityManifest,
    ScannerDeploymentMode,
    ScannerEvidenceReference,
    ScannerExecutionLimits,
    ScannerJobState,
    ScannerKind,
)

NUCLEI_EXECUTION_SCHEMA_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE = Literal["passive", "standard", "intrusive", "retest"]
_MAX_READINESS_AGE = timedelta(minutes=15)

_ALLOWED_TRANSITIONS: dict[ScannerJobState, frozenset[ScannerJobState]] = {
    ScannerJobState.PREPARED: frozenset(
        {
            ScannerJobState.VALIDATED,
            ScannerJobState.BLOCKED_EXECUTION_DISABLED,
            ScannerJobState.CANCELLED,
            ScannerJobState.FAILED,
        }
    ),
    ScannerJobState.VALIDATED: frozenset(
        {
            ScannerJobState.BLOCKED_EXECUTION_DISABLED,
            ScannerJobState.STARTING,
            ScannerJobState.CANCELLED,
            ScannerJobState.FAILED,
        }
    ),
    ScannerJobState.STARTING: frozenset(
        {
            ScannerJobState.RUNNING,
            ScannerJobState.CANCELLING,
            ScannerJobState.CANCELLED,
            ScannerJobState.TIMED_OUT,
            ScannerJobState.FAILED,
        }
    ),
    ScannerJobState.RUNNING: frozenset(
        {
            ScannerJobState.CANCELLING,
            ScannerJobState.CANCELLED,
            ScannerJobState.TIMED_OUT,
            ScannerJobState.FAILED,
            ScannerJobState.COMPLETED,
        }
    ),
    ScannerJobState.CANCELLING: frozenset(
        {
            ScannerJobState.CANCELLED,
            ScannerJobState.TIMED_OUT,
            ScannerJobState.FAILED,
        }
    ),
    ScannerJobState.BLOCKED_EXECUTION_DISABLED: frozenset(),
    ScannerJobState.CANCELLED: frozenset(),
    ScannerJobState.TIMED_OUT: frozenset(),
    ScannerJobState.FAILED: frozenset(),
    ScannerJobState.COMPLETED: frozenset(),
}
_UNFINISHED_STATES = frozenset(
    {
        ScannerJobState.PREPARED,
        ScannerJobState.VALIDATED,
        ScannerJobState.STARTING,
        ScannerJobState.RUNNING,
        ScannerJobState.CANCELLING,
    }
)


class NucleiExecutionError(RuntimeError):
    """Raised when the controlled execution harness fails closed."""


class DuplicateNucleiExecutionError(NucleiExecutionError):
    """Raised when an execution ID has already been persisted."""


def _identifier(value: str) -> str:
    normalized = value.strip().lower()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError("identifier must be a stable lowercase value")
    return normalized


def _digest(value: str, *, field: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a SHA-256 digest")
    return value


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _safe_reason(value: str) -> str:
    return redact_text(value).strip()[:300] or "No additional reason supplied."


def _digest_token(value: str) -> str:
    """Encode a SHA-256 value without payment-card-like digit runs."""
    return base64.urlsafe_b64encode(bytes.fromhex(value)).decode("ascii").rstrip("=")


class NucleiRuntimeReadiness(BaseModel):
    """Fresh local version evidence rechecked immediately before the runner boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    engine_version: str
    template_release: str
    template_manifest_hashes: tuple[str, ...] = Field(min_length=1)
    compatibility_manifest_sha256: str
    checked_at: datetime
    execution_enabled: Literal[False] = False

    @field_validator("template_manifest_hashes")
    @classmethod
    def validate_template_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("readiness template hashes must be SHA-256 values")
        return tuple(sorted(set(values)))

    @field_validator("compatibility_manifest_sha256")
    @classmethod
    def validate_compatibility_digest(cls, value: str) -> str:
        return _digest(value, field="compatibility_manifest_sha256")

    @field_validator("checked_at")
    @classmethod
    def validate_checked_at(cls, value: datetime) -> datetime:
        return _utc(value, field="checked_at")


class NucleiExecutionRequest(BaseModel):
    """Immutable request bound to one exact plan and approval.

    The model intentionally has no command string, argv, process environment,
    credential, proxy, header, or token field.  Extra input is forbidden.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[NUCLEI_EXECUTION_SCHEMA_VERSION] = NUCLEI_EXECUTION_SCHEMA_VERSION
    protocol_version: Literal[SCANNER_PROTOCOL_VERSION] = SCANNER_PROTOCOL_VERSION
    execution_id: str
    authorization_id: str
    approval_id: str
    plan_digest: str
    exact_targets: tuple[ScopedNucleiTarget, ...] = Field(min_length=1)
    exact_profile: _PROFILE
    template_manifest_hashes: tuple[str, ...] = Field(min_length=1)
    output_directory: Path
    expires_at: datetime
    limits: ScannerExecutionLimits
    cancellation_id: str
    correlation_id: str
    compatibility_manifest_sha256: str
    secret_provider_id: str | None = None
    execution_enabled: Literal[False] = False

    @field_validator(
        "execution_id",
        "authorization_id",
        "approval_id",
        "cancellation_id",
        "correlation_id",
    )
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("secret_provider_id")
    @classmethod
    def validate_secret_provider_id(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value)

    @field_validator("plan_digest", "compatibility_manifest_sha256")
    @classmethod
    def validate_digests(cls, value: str, info) -> str:
        return _digest(value, field=info.field_name)

    @field_validator("template_manifest_hashes")
    @classmethod
    def validate_template_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("template manifest hashes must be SHA-256 values")
        return tuple(sorted(set(values)))

    @field_validator("output_directory")
    @classmethod
    def validate_output_directory(cls, value: Path) -> Path:
        expanded = value.expanduser()
        if not expanded.is_absolute():
            raise ValueError("execution output directory must be absolute")
        return expanded

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime) -> datetime:
        return _utc(value, field="expires_at")

    @model_validator(mode="after")
    def validate_unique_targets(self) -> Self:
        target_urls = [target.url for target in self.exact_targets]
        if len(target_urls) != len(set(target_urls)):
            raise ValueError("execution targets must be unique")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    @classmethod
    def from_plan(
        cls,
        *,
        execution_id: str,
        plan: NucleiCommandPlan,
        approval: NucleiPlanApproval,
        limits: ScannerExecutionLimits,
        cancellation_id: str,
        correlation_id: str,
        compatibility_manifest_sha256: str,
        secret_provider_id: str | None = None,
    ) -> Self:
        return cls(
            execution_id=execution_id,
            authorization_id=plan.authorization_id,
            approval_id=approval.approval_id,
            plan_digest=plan.plan_digest,
            exact_targets=plan.exact_targets,
            exact_profile=plan.exact_profile,
            template_manifest_hashes=plan.template_manifest_hashes,
            output_directory=plan.output_directory,
            expires_at=plan.expires_at,
            limits=limits,
            cancellation_id=cancellation_id,
            correlation_id=correlation_id,
            compatibility_manifest_sha256=compatibility_manifest_sha256,
            secret_provider_id=secret_provider_id,
        )


class BoundedTextCapture(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    captured_bytes: int = Field(ge=0)
    truncated: bool
    sha256: str

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return _digest(value, field="sha256")

    @classmethod
    def capture(cls, value: str, *, maximum_bytes: int) -> Self:
        if maximum_bytes < 1:
            raise ValueError("maximum_bytes must be positive")
        redacted = redact_text(value)
        encoded = redacted.encode("utf-8")
        truncated = len(encoded) > maximum_bytes
        stored = encoded[:maximum_bytes]
        while stored:
            try:
                text = stored.decode("utf-8")
                break
            except UnicodeDecodeError:
                stored = stored[:-1]
        else:
            text = ""
        return cls(
            text=text,
            captured_bytes=len(stored),
            truncated=truncated,
            sha256=hashlib.sha256(stored).hexdigest(),
        )


class NucleiRunnerResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    state: Literal[
        ScannerJobState.BLOCKED_EXECUTION_DISABLED,
        ScannerJobState.CANCELLED,
        ScannerJobState.TIMED_OUT,
        ScannerJobState.FAILED,
        ScannerJobState.COMPLETED,
    ]
    reason: str
    stdout: str = ""
    stderr: str = ""
    observations: tuple[ScannerCandidateObservation, ...] = ()

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _safe_reason(value)


class NucleiExecutionTransition(BaseModel):
    """Hash-linked state transition written for every lifecycle change."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=1)
    execution_id: str
    authorization_id: str
    plan_digest: str
    previous_state: ScannerJobState | None
    new_state: ScannerJobState
    occurred_at: datetime
    actor_id: str
    reason: str
    correlation_id: str
    previous_event_sha256: str = "0" * 64
    event_sha256: str

    @field_validator("execution_id", "authorization_id", "actor_id", "correlation_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("plan_digest", "previous_event_sha256", "event_sha256")
    @classmethod
    def validate_digests(cls, value: str, info) -> str:
        return _digest(value, field=info.field_name)

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return _utc(value, field="occurred_at")

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _safe_reason(value)

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"event_sha256"})

    def expected_sha256(self) -> str:
        return sha256_json(self.unsigned_payload())

    @classmethod
    def create(cls, **values: object) -> Self:
        if "event_sha256" in values:
            raise ValueError("event_sha256 is calculated, not caller supplied")
        temporary = cls.model_construct(**values, event_sha256="0" * 64)
        return cls(**values, event_sha256=sha256_json(temporary.unsigned_payload()))


class NucleiExecutionRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request: NucleiExecutionRequest
    state: ScannerJobState
    created_at: datetime
    updated_at: datetime
    timeout_deadline: datetime
    cancellation_requested: bool = False
    cancellation_reason: str | None = None
    last_transition_sha256: str
    stdout: BoundedTextCapture | None = None
    stderr: BoundedTextCapture | None = None
    observations: tuple[ScannerCandidateObservation, ...] = ()
    evidence: tuple[ScannerEvidenceReference, ...] = ()

    @field_validator("created_at", "updated_at", "timeout_deadline")
    @classmethod
    def validate_times(cls, value: datetime, info) -> datetime:
        return _utc(value, field=info.field_name)

    @field_validator("last_transition_sha256")
    @classmethod
    def validate_last_transition_sha256(cls, value: str) -> str:
        return _digest(value, field="last_transition_sha256")

    @field_validator("cancellation_reason")
    @classmethod
    def validate_cancellation_reason(cls, value: str | None) -> str | None:
        return None if value is None else _safe_reason(value)


class NucleiExecutionStore:
    """File-backed execution records plus append-only hash-linked transitions."""

    def __init__(self, root: Path) -> None:
        lexical = root.expanduser().absolute()
        lexical.mkdir(parents=True, exist_ok=True)
        if lexical.is_symlink():
            raise NucleiExecutionError("execution store root must not be a symbolic link")
        self.root = lexical.resolve(strict=True)
        self.records = self.root / "records"
        self.events = self.root / "events"
        self.records.mkdir(exist_ok=True)
        self.events.mkdir(exist_ok=True)
        if self.records.is_symlink() or self.events.is_symlink():
            raise NucleiExecutionError("execution store directories must not be symbolic links")
        self._lock = threading.RLock()

    def _record_path(self, execution_id: str) -> Path:
        return self.records / f"{_identifier(execution_id)}.json"

    def _event_path(self, execution_id: str) -> Path:
        return self.events / f"{_identifier(execution_id)}.jsonl"

    @staticmethod
    def _write_atomic(path: Path, content: str) -> None:
        if path.is_symlink():
            raise NucleiExecutionError("execution record path must not be a symbolic link")
        temporary = path.with_suffix(path.suffix + ".part")
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        os.replace(temporary, path)

    def _append_event(self, event: NucleiExecutionTransition) -> None:
        path = self._event_path(event.execution_id)
        if path.is_symlink():
            raise NucleiExecutionError("execution event path must not be a symbolic link")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "a", encoding="utf-8", closefd=False) as handle:
                handle.write(event.model_dump_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)

    def prepare(
        self,
        request: NucleiExecutionRequest,
        *,
        actor_id: str,
        now: datetime,
    ) -> NucleiExecutionRecord:
        current = _utc(now, field="now")
        with self._lock:
            path = self._record_path(request.execution_id)
            if path.exists() or self._event_path(request.execution_id).exists():
                raise DuplicateNucleiExecutionError(
                    f"execution ID already exists: {request.execution_id}"
                )
            transition = NucleiExecutionTransition.create(
                sequence=1,
                execution_id=request.execution_id,
                authorization_id=request.authorization_id,
                plan_digest=request.plan_digest,
                previous_state=None,
                new_state=ScannerJobState.PREPARED,
                occurred_at=current,
                actor_id=actor_id,
                reason="Controlled execution request prepared.",
                correlation_id=request.correlation_id,
                previous_event_sha256="0" * 64,
            )
            record = NucleiExecutionRecord(
                request=request,
                state=ScannerJobState.PREPARED,
                created_at=current,
                updated_at=current,
                timeout_deadline=current + timedelta(seconds=request.limits.timeout_seconds),
                last_transition_sha256=transition.event_sha256,
            )
            self._write_atomic(path, record.model_dump_json(indent=2) + "\n")
            self._append_event(transition)
            return record

    def load(self, execution_id: str) -> NucleiExecutionRecord:
        path = self._record_path(execution_id)
        if path.is_symlink():
            raise NucleiExecutionError("execution record must not be a symbolic link")
        try:
            return NucleiExecutionRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise NucleiExecutionError(f"unknown execution ID: {execution_id}") from exc
        except ValidationError as exc:
            raise NucleiExecutionError("persisted execution record is invalid") from exc

    def list_events(self, execution_id: str) -> tuple[NucleiExecutionTransition, ...]:
        path = self._event_path(execution_id)
        if not path.exists():
            return ()
        if path.is_symlink():
            raise NucleiExecutionError("execution event ledger must not be a symbolic link")
        events: list[NucleiExecutionTransition] = []
        previous_digest = "0" * 64
        previous_state: ScannerJobState | None = None
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = NucleiExecutionTransition.model_validate_json(line)
            except ValidationError as exc:
                raise NucleiExecutionError(
                    f"execution event line {line_number} is invalid"
                ) from exc
            if event.previous_event_sha256 != previous_digest:
                raise NucleiExecutionError("execution event hash chain has been altered")
            if event.expected_sha256() != event.event_sha256:
                raise NucleiExecutionError("execution event digest does not match")
            if event.previous_state != previous_state:
                raise NucleiExecutionError("execution event state chain has been altered")
            previous_digest = event.event_sha256
            previous_state = event.new_state
            events.append(event)
        return tuple(events)

    def transition(
        self,
        execution_id: str,
        new_state: ScannerJobState,
        *,
        actor_id: str,
        reason: str,
        now: datetime,
        stdout: BoundedTextCapture | None = None,
        stderr: BoundedTextCapture | None = None,
        observations: tuple[ScannerCandidateObservation, ...] | None = None,
        evidence: tuple[ScannerEvidenceReference, ...] | None = None,
    ) -> NucleiExecutionRecord:
        current = _utc(now, field="now")
        with self._lock:
            record = self.load(execution_id)
            if new_state not in _ALLOWED_TRANSITIONS[record.state]:
                raise NucleiExecutionError(
                    f"invalid execution transition: {record.state.value} -> {new_state.value}"
                )
            events = self.list_events(execution_id)
            sequence = len(events) + 1
            transition = NucleiExecutionTransition.create(
                sequence=sequence,
                execution_id=record.request.execution_id,
                authorization_id=record.request.authorization_id,
                plan_digest=record.request.plan_digest,
                previous_state=record.state,
                new_state=new_state,
                occurred_at=current,
                actor_id=actor_id,
                reason=reason,
                correlation_id=record.request.correlation_id,
                previous_event_sha256=record.last_transition_sha256,
            )
            updated = record.model_copy(
                update={
                    "state": new_state,
                    "updated_at": current,
                    "last_transition_sha256": transition.event_sha256,
                    "stdout": stdout if stdout is not None else record.stdout,
                    "stderr": stderr if stderr is not None else record.stderr,
                    "observations": (
                        observations if observations is not None else record.observations
                    ),
                    "evidence": evidence if evidence is not None else record.evidence,
                }
            )
            self._write_atomic(
                self._record_path(execution_id),
                updated.model_dump_json(indent=2) + "\n",
            )
            self._append_event(transition)
            return updated

    def request_cancellation(
        self,
        execution_id: str,
        *,
        reason: str,
        actor_id: str,
        now: datetime,
    ) -> NucleiExecutionRecord:
        current = _utc(now, field="now")
        with self._lock:
            record = self.load(execution_id)
            if record.cancellation_requested:
                return record
            safe_reason = _safe_reason(reason)
            updated = record.model_copy(
                update={
                    "cancellation_requested": True,
                    "cancellation_reason": safe_reason,
                    "updated_at": current,
                }
            )
            self._write_atomic(
                self._record_path(execution_id),
                updated.model_dump_json(indent=2) + "\n",
            )
            if record.state in {ScannerJobState.STARTING, ScannerJobState.RUNNING}:
                return self.transition(
                    execution_id,
                    ScannerJobState.CANCELLING,
                    actor_id=actor_id,
                    reason=safe_reason,
                    now=current,
                )
            return updated

    def recover_unfinished(
        self,
        *,
        actor_id: str,
        now: datetime,
    ) -> tuple[NucleiExecutionRecord, ...]:
        recovered: list[NucleiExecutionRecord] = []
        for path in sorted(self.records.glob("*.json")):
            if path.is_symlink():
                raise NucleiExecutionError("execution record must not be a symbolic link")
            record = self.load(path.stem)
            if record.state in _UNFINISHED_STATES:
                target_state = (
                    ScannerJobState.BLOCKED_EXECUTION_DISABLED
                    if record.state
                    in {
                        ScannerJobState.PREPARED,
                        ScannerJobState.VALIDATED,
                    }
                    else ScannerJobState.FAILED
                )
                recovered.append(
                    self.transition(
                        record.request.execution_id,
                        target_state,
                        actor_id=actor_id,
                        reason=(
                            "Unfinished execution recovered fail-closed while production "
                            "execution remains disabled."
                        ),
                        now=now,
                    )
                )
        return tuple(recovered)


class NucleiValidatedSpecification(BaseModel):
    """Internal runner input produced only after complete revalidation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request: NucleiExecutionRequest
    plan: NucleiCommandPlan
    approval: NucleiPlanApproval
    readiness: NucleiRuntimeReadiness
    validated_at: datetime

    @field_validator("validated_at")
    @classmethod
    def validate_validated_at(cls, value: datetime) -> datetime:
        return _utc(value, field="validated_at")


class NucleiRunner(Protocol):
    """Runner boundary. Production implementation in this milestone only blocks."""

    is_test_double: bool

    def run(
        self,
        specification: NucleiValidatedSpecification,
        *,
        control: NucleiRunControl,
    ) -> NucleiRunnerResult: ...


class _NoProcessTerminator:
    """Termination implementation used while no process can exist."""

    def terminate_process_group(self, process_group_id: int, *, grace_seconds: float) -> None:
        raise NucleiExecutionError("no process group exists in the disabled execution harness")


class _StoreAwareRunControl(NucleiRunControl):
    """Bridge persisted cancellation requests into cooperative runner checkpoints."""

    def __init__(
        self,
        *,
        store: NucleiExecutionStore,
        execution_id: str,
        timeout_seconds: float,
        terminator: ProcessGroupTerminator,
        monotonic: Callable[[], float],
        grace_seconds: float,
    ) -> None:
        super().__init__(
            timeout_seconds=timeout_seconds,
            terminator=terminator,
            monotonic=monotonic,
            grace_seconds=grace_seconds,
        )
        self._store = store
        self._execution_id = execution_id

    def checkpoint(self, *, process_group_id: int | None = None) -> None:
        record = self._store.load(self._execution_id)
        if record.cancellation_requested:
            self.cancel(record.cancellation_reason or "Cancellation requested.")
        super().checkpoint(process_group_id=process_group_id)


class DisabledNucleiRunner:
    """Production runner that cannot create a subprocess or network operation."""

    is_test_double = False

    def run(
        self,
        specification: NucleiValidatedSpecification,
        *,
        control: NucleiRunControl,
    ) -> NucleiRunnerResult:
        del specification, control
        return NucleiRunnerResult(
            state=ScannerJobState.BLOCKED_EXECUTION_DISABLED,
            reason="Nuclei production execution remains globally disabled.",
        )


class DeterministicFakeRunner:
    """No-process, no-network test double for lifecycle verification only."""

    is_test_double = True

    def __init__(
        self,
        *,
        scenario: Literal["success", "failure", "cancelled", "timed_out"] = "success",
        stdout: str = "fake-runner completed",
        stderr: str = "",
        observations: tuple[ScannerCandidateObservation, ...] = (),
    ) -> None:
        self.scenario = scenario
        self.stdout = stdout
        self.stderr = stderr
        self.observations = observations
        self.calls = 0

    def run(
        self,
        specification: NucleiValidatedSpecification,
        *,
        control: NucleiRunControl,
    ) -> NucleiRunnerResult:
        del specification
        self.calls += 1
        if self.scenario == "cancelled":
            control.cancel("deterministic fake cancellation")
            control.checkpoint()
        if self.scenario == "timed_out":
            raise NucleiTimeoutError("deterministic fake timeout")
        if self.scenario == "failure":
            return NucleiRunnerResult(
                state=ScannerJobState.FAILED,
                reason="Deterministic fake runner failure.",
                stdout=self.stdout,
                stderr=self.stderr or "fake failure",
            )
        return NucleiRunnerResult(
            state=ScannerJobState.COMPLETED,
            reason="Deterministic fake runner completed.",
            stdout=self.stdout,
            stderr=self.stderr,
            observations=self.observations,
        )


class NucleiExecutionInvocation(BaseModel):
    """Manager-side invocation passed to the Nuclei scanner adapter."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    request: NucleiExecutionRequest
    plan: NucleiCommandPlan
    approval: NucleiPlanApproval
    authorization: EngagementAuthorization
    readiness: NucleiRuntimeReadiness
    actor_id: str
    now: datetime

    @field_validator("actor_id")
    @classmethod
    def validate_actor_id(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("now")
    @classmethod
    def validate_now(cls, value: datetime) -> datetime:
        return _utc(value, field="now")


class NucleiExecutionHarness:
    """Revalidate, persist, and route a governed request to a disabled or fake runner."""

    def __init__(
        self,
        *,
        store: NucleiExecutionStore,
        runner: NucleiRunner,
        resolver: AddressResolver,
        approved_output_root: Path,
        compatibility_manifest: ScannerCompatibilityManifest,
        allow_test_runner: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
        terminator: ProcessGroupTerminator | None = None,
        maximum_concurrency: int = 2,
    ) -> None:
        if not 1 <= maximum_concurrency <= 2:
            raise ValueError("maximum_concurrency must be between one and two")
        if runner.is_test_double and not allow_test_runner:
            raise ValueError("test runner requires explicit test-only enablement")
        self.store = store
        self.runner = runner
        self.resolver = resolver
        self.approved_output_root = approved_output_root.expanduser().absolute()
        self.compatibility_manifest = compatibility_manifest
        self.allow_test_runner = allow_test_runner
        self.monotonic = monotonic
        self.terminator = terminator or _NoProcessTerminator()
        self._slots = threading.BoundedSemaphore(maximum_concurrency)

    def _revalidate(
        self,
        invocation: NucleiExecutionInvocation,
    ) -> NucleiValidatedSpecification:
        request = invocation.request
        plan = invocation.plan
        approval = invocation.approval
        authorization = invocation.authorization
        readiness = invocation.readiness
        now = invocation.now

        if request.execution_enabled is not False or readiness.execution_enabled is not False:
            raise NucleiExecutionError("Nuclei execution remains globally disabled")
        if request.authorization_id != authorization.authorization_id:
            raise NucleiExecutionError("execution authorization does not match the engagement")
        if request.authorization_id != plan.authorization_id:
            raise NucleiExecutionError("execution authorization does not match the plan")
        if request.approval_id != approval.approval_id:
            raise NucleiExecutionError("execution approval does not match the approved record")
        if request.plan_digest != plan.plan_digest or plan.plan_digest != plan.fingerprint():
            raise NucleiExecutionError("execution requires the exact command-plan digest")
        if request.exact_targets != plan.exact_targets:
            raise NucleiExecutionError("execution target scope differs from the command plan")
        if request.exact_profile != plan.exact_profile:
            raise NucleiExecutionError("execution profile differs from the command plan")
        if request.template_manifest_hashes != plan.template_manifest_hashes:
            raise NucleiExecutionError("execution templates differ from the command plan")
        if request.output_directory != plan.output_directory:
            raise NucleiExecutionError("execution evidence directory differs from the command plan")
        if request.expires_at != plan.expires_at or now >= request.expires_at:
            raise NucleiExecutionError("execution request or command plan has expired")
        if request.limits.concurrency != plan.concurrency:
            raise NucleiExecutionError("execution concurrency differs from the approved plan")
        if request.limits.rate_limit != plan.rate_limit:
            raise NucleiExecutionError("execution rate limit differs from the approved plan")

        actual_compatibility_digest = self.compatibility_manifest.fingerprint()
        if request.compatibility_manifest_sha256 != actual_compatibility_digest:
            raise NucleiExecutionError("scanner compatibility manifest changed before execution")
        if readiness.compatibility_manifest_sha256 != actual_compatibility_digest:
            raise NucleiExecutionError("readiness used another scanner compatibility manifest")

        try:
            compatibility = self.compatibility_manifest.get("nuclei")
        except KeyError as exc:
            raise NucleiExecutionError("Nuclei compatibility record is missing") from exc
        pin = compatibility.version_pin
        if compatibility.descriptor.status not in {
            ScannerAdapterStatus.HARNESS_ONLY,
            ScannerAdapterStatus.PILOT_READY,
        }:
            raise NucleiExecutionError("Nuclei adapter has not passed harness or pilot review")
        if pin.engine_version != readiness.engine_version:
            raise NucleiExecutionError("Nuclei engine version does not match the reviewed pin")
        if pin.feed is None or pin.feed.release != readiness.template_release:
            raise NucleiExecutionError("Nuclei template release does not match the reviewed pin")
        if readiness.template_manifest_hashes != request.template_manifest_hashes:
            raise NucleiExecutionError("Nuclei template hashes changed after readiness validation")
        if readiness.checked_at > now or now - readiness.checked_at > _MAX_READINESS_AGE:
            raise NucleiExecutionError("Nuclei readiness evidence is stale")

        try:
            validate_nuclei_plan_approval(
                plan,
                approval,
                authorization=authorization,
                resolver=self.resolver,
                approved_output_root=self.approved_output_root,
                approved_template_manifest_hashes=request.template_manifest_hashes,
                now=now,
                execution_enabled=False,
            )
        except NucleiActivationError as exc:
            raise NucleiExecutionError(str(exc)) from exc

        return NucleiValidatedSpecification(
            request=request,
            plan=plan,
            approval=approval,
            readiness=readiness,
            validated_at=now,
        )

    @staticmethod
    def _sanitize_observations(
        observations: tuple[ScannerCandidateObservation, ...],
    ) -> tuple[ScannerCandidateObservation, ...]:
        sanitized: list[ScannerCandidateObservation] = []
        for observation in observations:
            safe_metadata = redact_mapping(dict(observation.metadata))
            sanitized.append(
                observation.model_copy(
                    update={
                        "title": redact_text(observation.title)[:500],
                        "severity": redact_text(observation.severity)[:32],
                        "confidence": redact_text(observation.confidence)[:32],
                        "metadata": safe_metadata,
                    }
                )
            )
        return tuple(sanitized)

    def _persist_summary(
        self,
        *,
        request: NucleiExecutionRequest,
        result: NucleiRunnerResult,
        stdout: BoundedTextCapture,
        stderr: BoundedTextCapture,
        observations: tuple[ScannerCandidateObservation, ...],
    ) -> ScannerEvidenceReference:
        output_directory = validate_evidence_directory(
            request.output_directory,
            approved_root=self.approved_output_root,
        )
        path = output_directory / f"execution-{request.execution_id}.jsonl"
        if path.exists() or path.is_symlink():
            raise NucleiExecutionError("execution evidence summary already exists")
        payload = {
            "schema_version": NUCLEI_EXECUTION_SCHEMA_VERSION,
            "execution_reference": _digest_token(
                hashlib.sha256(request.execution_id.encode("utf-8")).hexdigest()
            ),
            "authorization_reference": _digest_token(
                hashlib.sha256(request.authorization_id.encode("utf-8")).hexdigest()
            ),
            "plan_reference": _digest_token(request.plan_digest),
            "state": result.state.value,
            "reason": _safe_reason(result.reason),
            "stdout": {
                "text": stdout.text,
                "captured_bytes": stdout.captured_bytes,
                "truncated": stdout.truncated,
                "content_reference": _digest_token(stdout.sha256),
            },
            "stderr": {
                "text": stderr.text,
                "captured_bytes": stderr.captured_bytes,
                "truncated": stderr.truncated,
                "content_reference": _digest_token(stderr.sha256),
            },
            "observations": [
                {
                    "title": item.title,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "finding_status": "candidate",
                    "metadata": dict(item.metadata),
                }
                for item in observations
            ],
        }
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        maximum_bytes = min(
            4_000_000,
            request.limits.maximum_stdout_bytes + request.limits.maximum_stderr_bytes + 64_000,
        )
        if len(encoded) > maximum_bytes:
            raise NucleiExecutionError("execution evidence summary exceeds its bounded limit")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        try:
            evidence_sha256 = verify_redacted_evidence(path, maximum_bytes=maximum_bytes)
        except NucleiActivationError as exc:
            path.unlink(missing_ok=True)
            raise NucleiExecutionError("execution evidence failed redaction validation") from exc
        return ScannerEvidenceReference(
            relative_path=str(path.relative_to(self.approved_output_root.resolve(strict=True))),
            sha256=evidence_sha256,
            size_bytes=len(encoded),
            media_type="application/x-ndjson",
        )

    def execute(self, invocation: NucleiExecutionInvocation) -> NucleiExecutionRecord:
        request = invocation.request
        self.store.prepare(request, actor_id=invocation.actor_id, now=invocation.now)
        try:
            specification = self._revalidate(invocation)
        except (NucleiExecutionError, OSError, ValueError) as exc:
            return self.store.transition(
                request.execution_id,
                ScannerJobState.FAILED,
                actor_id=invocation.actor_id,
                reason=str(exc),
                now=invocation.now,
            )

        record = self.store.transition(
            request.execution_id,
            ScannerJobState.VALIDATED,
            actor_id=invocation.actor_id,
            reason="Authorization, plan, approval, target, evidence, and version pins revalidated.",
            now=invocation.now,
        )
        if record.cancellation_requested:
            return self.store.transition(
                request.execution_id,
                ScannerJobState.CANCELLED,
                actor_id=invocation.actor_id,
                reason=record.cancellation_reason or "Cancellation requested before start.",
                now=invocation.now,
            )

        if self.runner.is_test_double:
            if not self.allow_test_runner:
                raise NucleiExecutionError("test runner is unavailable outside tests")
            acquired = self._slots.acquire(blocking=False)
            if not acquired:
                return self.store.transition(
                    request.execution_id,
                    ScannerJobState.FAILED,
                    actor_id=invocation.actor_id,
                    reason="Scanner concurrency limit reached.",
                    now=invocation.now,
                )
            self.store.transition(
                request.execution_id,
                ScannerJobState.STARTING,
                actor_id=invocation.actor_id,
                reason="Deterministic test runner starting.",
                now=invocation.now,
            )
            self.store.transition(
                request.execution_id,
                ScannerJobState.RUNNING,
                actor_id=invocation.actor_id,
                reason="Deterministic test runner running without subprocess or network.",
                now=invocation.now,
            )
        else:
            acquired = False

        control = _StoreAwareRunControl(
            store=self.store,
            execution_id=request.execution_id,
            timeout_seconds=request.limits.timeout_seconds,
            terminator=self.terminator,
            monotonic=self.monotonic,
            grace_seconds=request.limits.termination_grace_seconds,
        )
        try:
            result = self.runner.run(specification, control=control)
        except NucleiCancellationError as exc:
            result = NucleiRunnerResult(
                state=ScannerJobState.CANCELLED,
                reason=str(exc),
            )
        except NucleiTimeoutError as exc:
            result = NucleiRunnerResult(
                state=ScannerJobState.TIMED_OUT,
                reason=str(exc),
            )
        except Exception as exc:  # pragma: no cover - defensive adapter boundary
            result = NucleiRunnerResult(
                state=ScannerJobState.FAILED,
                reason=f"Scanner adapter failed closed: {type(exc).__name__}",
            )
        finally:
            if acquired:
                self._slots.release()

        stdout = BoundedTextCapture.capture(
            result.stdout,
            maximum_bytes=request.limits.maximum_stdout_bytes,
        )
        stderr = BoundedTextCapture.capture(
            result.stderr,
            maximum_bytes=request.limits.maximum_stderr_bytes,
        )
        observations = self._sanitize_observations(result.observations)
        evidence = self._persist_summary(
            request=request,
            result=result,
            stdout=stdout,
            stderr=stderr,
            observations=observations,
        )

        current = self.store.load(request.execution_id)
        target_state = result.state
        if (
            current.state is ScannerJobState.CANCELLING
            and target_state is not ScannerJobState.CANCELLED
        ):
            target_state = ScannerJobState.CANCELLED
        return self.store.transition(
            request.execution_id,
            target_state,
            actor_id=invocation.actor_id,
            reason=result.reason,
            now=invocation.now,
            stdout=stdout,
            stderr=stderr,
            observations=observations,
            evidence=(evidence,),
        )

    def request_cancellation(
        self,
        execution_id: str,
        *,
        reason: str,
        actor_id: str,
        now: datetime,
    ) -> NucleiExecutionRecord:
        return self.store.request_cancellation(
            execution_id,
            reason=reason,
            actor_id=actor_id,
            now=now,
        )

    def recover_unfinished(
        self,
        *,
        actor_id: str,
        now: datetime,
    ) -> tuple[NucleiExecutionRecord, ...]:
        return self.store.recover_unfinished(actor_id=actor_id, now=now)


class NucleiScannerAdapter:
    """Formal scanner adapter connecting the manager protocol to the harness."""

    def __init__(self, harness: NucleiExecutionHarness) -> None:
        self.harness = harness
        self._descriptor = ScannerAdapterDescriptor(
            adapter_id="nuclei-controlled-harness",
            scanner_kind=ScannerKind.NUCLEI,
            status=ScannerAdapterStatus.HARNESS_ONLY,
            deployment_mode=ScannerDeploymentMode.ISOLATED_CONTAINER,
            supported_profiles=("passive", "standard", "intrusive", "retest"),
        )

    @property
    def descriptor(self) -> ScannerAdapterDescriptor:
        return self._descriptor

    def submit(self, request: object) -> ScannerAdapterResult:
        if not isinstance(request, NucleiExecutionInvocation):
            raise TypeError("Nuclei adapter requires a NucleiExecutionInvocation")
        record = self.harness.execute(request)
        return ScannerAdapterResult(
            execution_id=record.request.execution_id,
            state=record.state,
            observations=record.observations,
            evidence=record.evidence,
            reason=self.harness.store.list_events(record.request.execution_id)[-1].reason,
        )


__all__ = [
    "BoundedTextCapture",
    "DeterministicFakeRunner",
    "DisabledNucleiRunner",
    "DuplicateNucleiExecutionError",
    "NucleiExecutionError",
    "NucleiExecutionHarness",
    "NucleiExecutionInvocation",
    "NucleiExecutionRecord",
    "NucleiExecutionRequest",
    "NucleiExecutionStore",
    "NucleiExecutionTransition",
    "NucleiRunner",
    "NucleiRunnerResult",
    "NucleiRuntimeReadiness",
    "NucleiScannerAdapter",
    "NucleiValidatedSpecification",
]
