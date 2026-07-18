"""Signed local spool connecting the manager to isolated scanner workers."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.nuclei_execution import (
    NucleiExecutionInvocation,
    NucleiExecutionRecord,
)


class WorkerSpoolError(RuntimeError):
    """Raised when a worker envelope or spool boundary fails closed."""


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def load_worker_signing_key(path: Path) -> bytes:
    """Load an owner-private signing key without persisting it in job files."""

    candidate = path.expanduser()
    if candidate.is_symlink():
        raise WorkerSpoolError("worker signing key must not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise WorkerSpoolError("worker signing key is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise WorkerSpoolError("worker signing key must be a regular file")
    if metadata.st_uid != os.getuid():
        raise WorkerSpoolError("worker signing key must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise WorkerSpoolError("worker signing key permissions must be 0600 or stricter")
    try:
        value = resolved.read_bytes().strip()
    except OSError as exc:
        raise WorkerSpoolError("worker signing key could not be read") from exc
    if len(value) < 32 or len(value) > 512:
        raise WorkerSpoolError("worker signing key must contain 32 to 512 bytes")
    return value


class SignedNucleiWorkerJob(BaseModel):
    """Immutable, expiring and authenticated Nuclei worker request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    job_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    created_at: datetime
    expires_at: datetime
    invocation: NucleiExecutionInvocation
    invocation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime, info) -> datetime:
        return _utc(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("worker job expiry must be later than creation")
        if self.expires_at > self.invocation.request.expires_at:
            raise ValueError("worker job cannot outlive its execution request")
        if self.invocation_sha256 != sha256_json(self.invocation.model_dump(mode="json")):
            raise ValueError("worker job invocation digest does not match")
        return self

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def expected_signature(self, key: bytes) -> str:
        payload = json.dumps(
            self.unsigned_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    def verify(self, key: bytes, *, now: datetime) -> None:
        current = _utc(now, field="now")
        if current < self.created_at or current >= self.expires_at:
            raise WorkerSpoolError("worker job is not active")
        if not hmac.compare_digest(self.signature, self.expected_signature(key)):
            raise WorkerSpoolError("worker job signature is invalid")

    @classmethod
    def create(
        cls,
        *,
        job_id: str,
        invocation: NucleiExecutionInvocation,
        key: bytes,
        created_at: datetime,
    ) -> Self:
        created = _utc(created_at, field="created_at")
        provisional = cls.model_construct(
            schema_version="1.0",
            job_id=job_id,
            created_at=created,
            expires_at=invocation.request.expires_at,
            invocation=invocation,
            invocation_sha256=sha256_json(invocation.model_dump(mode="json")),
            signature="0" * 64,
        )
        return cls(
            **provisional.model_dump(exclude={"signature"}),
            signature=provisional.expected_signature(key),
        )


class WorkerJobReceipt(BaseModel):
    """Bounded terminal receipt written after a claimed job finishes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    job_id: str
    state: str
    execution_id: str
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _utc(value, field="completed_at")

    @classmethod
    def from_record(
        cls,
        *,
        job_id: str,
        record: NucleiExecutionRecord,
        completed_at: datetime,
    ) -> Self:
        return cls(
            job_id=job_id,
            state=record.state.value,
            execution_id=record.request.execution_id,
            result_sha256=sha256_json(record.model_dump(mode="json")),
            completed_at=completed_at,
            reason=(
                record.stderr.text if record.stderr and record.stderr.text else record.state.value
            )[:500],
        )


class SignedWorkerSpool:
    """Atomic single-host job spool with pending, processing and terminal areas."""

    def __init__(self, root: Path) -> None:
        lexical = root.expanduser().absolute()
        lexical.mkdir(parents=True, exist_ok=True)
        if lexical.is_symlink():
            raise WorkerSpoolError("worker spool root must not be a symbolic link")
        self.root = lexical.resolve(strict=True)
        self.pending = self._directory("pending")
        self.processing = self._directory("processing")
        self.completed = self._directory("completed")
        self.failed = self._directory("failed")

    def _directory(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise WorkerSpoolError("worker spool directory is unsafe")
        return path

    @staticmethod
    def _write_exclusive(path: Path, content: str) -> None:
        if path.exists() or path.is_symlink():
            raise WorkerSpoolError("worker job path already exists")
        descriptor = os.open(
            path,
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

    def enqueue(self, job: SignedNucleiWorkerJob) -> Path:
        path = self.pending / f"{job.job_id}.json"
        self._write_exclusive(path, job.model_dump_json(indent=2) + "\n")
        return path

    def claim_next(self) -> Path | None:
        for source in sorted(self.pending.glob("*.json")):
            if source.is_symlink():
                raise WorkerSpoolError("pending worker job must not be a symbolic link")
            destination = self.processing / source.name
            try:
                os.replace(source, destination)
            except FileNotFoundError:
                continue
            return destination
        return None

    def cancel_pending(self, job_id: str, *, reason: str, now: datetime) -> bool:
        source = self.pending / f"{job_id}.json"
        if not source.exists():
            return False
        if source.is_symlink():
            raise WorkerSpoolError("pending worker job must not be a symbolic link")
        destination = self.failed / source.name
        os.replace(source, destination)
        safe_reason = " ".join(reason.split())[:500] or "Worker job cancelled."
        receipt = WorkerJobReceipt(
            job_id=job_id,
            state="cancelled",
            execution_id="pending-job",
            result_sha256=hashlib.sha256(safe_reason.encode()).hexdigest(),
            completed_at=now,
            reason=safe_reason,
        )
        self._write_exclusive(
            self.failed / f"{job_id}.receipt.json",
            receipt.model_dump_json(indent=2) + "\n",
        )
        return True

    def load_claimed(
        self,
        path: Path,
        *,
        key: bytes,
        now: datetime,
    ) -> SignedNucleiWorkerJob:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.processing)
        except (OSError, ValueError) as exc:
            raise WorkerSpoolError("claimed worker job is outside the processing spool") from exc
        if path.is_symlink() or not resolved.is_file():
            raise WorkerSpoolError("claimed worker job is unsafe")
        try:
            job = SignedNucleiWorkerJob.model_validate_json(resolved.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise WorkerSpoolError("claimed worker job is invalid") from exc
        job.verify(key, now=now)
        return job

    def finish(
        self,
        claimed_path: Path,
        *,
        receipt: WorkerJobReceipt,
        success: bool,
    ) -> Path:
        target_root = self.completed if success else self.failed
        destination = target_root / claimed_path.name
        receipt_path = target_root / f"{claimed_path.stem}.receipt.json"
        self._write_exclusive(receipt_path, receipt.model_dump_json(indent=2) + "\n")
        os.replace(claimed_path, destination)
        return destination

    def reject(self, claimed_path: Path, *, reason: str, now: datetime) -> Path:
        safe_reason = " ".join(reason.split())[:500] or "Worker job rejected."
        digest = hashlib.sha256(safe_reason.encode()).hexdigest()
        receipt = WorkerJobReceipt(
            job_id=claimed_path.stem,
            state="rejected",
            execution_id="rejected-job",
            result_sha256=digest,
            completed_at=now,
            reason=safe_reason,
        )
        return self.finish(claimed_path, receipt=receipt, success=False)


__all__ = [
    "SignedNucleiWorkerJob",
    "SignedWorkerSpool",
    "WorkerJobReceipt",
    "WorkerSpoolError",
    "load_worker_signing_key",
]
