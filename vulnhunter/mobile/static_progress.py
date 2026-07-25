"""Signed, bounded live progress snapshots for mobile analysis jobs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

_JOB_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_TOOL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_MAX_EVENTS = 120
ToolState = Literal["planned", "running", "completed", "failed", "blocked"]
ProgressState = Literal["queued", "running", "completed", "failed", "blocked", "rejected"]


class MobileStaticProgressError(RuntimeError):
    """Raised when a progress snapshot cannot preserve its integrity boundary."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("progress timestamps must be timezone-aware")
    return value.astimezone(UTC)


class MobileProgressEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=1)
    at: datetime
    state: str
    stage: str = Field(min_length=1, max_length=64)
    detail: str = Field(min_length=1, max_length=500)
    tool: str | None = None
    tool_state: ToolState | None = None
    return_code: int | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("at")
    @classmethod
    def validate_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, value: str | None) -> str | None:
        if value is not None and _TOOL_ID.fullmatch(value) is None:
            raise ValueError("progress tool identifier is invalid")
        return value


class SignedMobileStaticProgress(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    job_id: str
    state: ProgressState
    active_tool: str | None = None
    tool_states: dict[str, ToolState] = Field(default_factory=dict)
    events: tuple[MobileProgressEvent, ...] = ()
    result_summary: dict[str, object] | None = None
    updated_at: datetime
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("job_id")
    @classmethod
    def validate_job_id(cls, value: str) -> str:
        if _JOB_ID.fullmatch(value) is None:
            raise ValueError("progress job identifier is invalid")
        return value

    @field_validator("updated_at")
    @classmethod
    def validate_updated_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("active_tool")
    @classmethod
    def validate_active_tool(cls, value: str | None) -> str | None:
        if value is not None and _TOOL_ID.fullmatch(value) is None:
            raise ValueError("active tool identifier is invalid")
        return value

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def expected_signature(self, key: bytes) -> str:
        encoded = json.dumps(
            self.unsigned_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(key, encoded, hashlib.sha256).hexdigest()

    def verify(self, key: bytes) -> None:
        if not hmac.compare_digest(self.signature, self.expected_signature(key)):
            raise MobileStaticProgressError("mobile progress signature is invalid")

    @classmethod
    def create(
        cls,
        *,
        job_id: str,
        state: ProgressState,
        active_tool: str | None,
        tool_states: dict[str, ToolState],
        events: tuple[MobileProgressEvent, ...],
        result_summary: dict[str, object] | None,
        updated_at: datetime,
        key: bytes,
    ) -> Self:
        provisional = cls.model_construct(
            schema_version="1.0",
            job_id=job_id,
            state=state,
            active_tool=active_tool,
            tool_states=tool_states,
            events=events,
            result_summary=result_summary,
            updated_at=_utc(updated_at),
            signature="0" * 64,
        )
        return cls(
            **provisional.model_dump(exclude={"signature"}),
            signature=provisional.expected_signature(key),
        )


class MobileStaticProgressStore:
    """Maintain one signed snapshot next to each owner-private spool job."""

    def __init__(self, root: Path) -> None:
        lexical = root.expanduser().absolute()
        lexical.mkdir(parents=True, exist_ok=True)
        if lexical.is_symlink():
            raise MobileStaticProgressError("progress root must not be a symbolic link")
        self.root = lexical.resolve(strict=True)
        self.processing = self._directory("processing")
        self.completed = self._directory("completed")
        self.failed = self._directory("failed")

    def _directory(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise MobileStaticProgressError("progress spool directory is unsafe")
        return path

    @staticmethod
    def _filename(job_id: str) -> str:
        if _JOB_ID.fullmatch(job_id) is None:
            raise MobileStaticProgressError("progress job identifier is invalid")
        return f"{job_id}.progress.json"

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _load_path(self, path: Path, *, key: bytes) -> SignedMobileStaticProgress:
        if path.is_symlink() or not path.is_file():
            raise MobileStaticProgressError("progress snapshot is unsafe")
        try:
            progress = SignedMobileStaticProgress.model_validate_json(
                path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise MobileStaticProgressError("progress snapshot is invalid") from exc
        progress.verify(key)
        return progress

    def append_event(
        self,
        *,
        job_id: str,
        event: dict[str, object],
        key: bytes,
    ) -> SignedMobileStaticProgress:
        job_path = self.processing / f"{job_id}.json"
        if not job_path.is_file() or job_path.is_symlink():
            raise MobileStaticProgressError("running job is unavailable for progress update")
        path = self.processing / self._filename(job_id)
        if path.exists():
            current = self._load_path(path, key=key)
            tool_states = dict(current.tool_states)
            events = list(current.events)
            result_summary = current.result_summary
        else:
            tools = event.get("tools")
            tool_states = {
                str(tool): "planned"
                for tool in tools
                if isinstance(tools, (list, tuple)) and isinstance(tool, str)
            }
            events = []
            result_summary = None
        tool = event.get("tool") if isinstance(event.get("tool"), str) else None
        tool_state = event.get("tool_state") if isinstance(event.get("tool_state"), str) else None
        if tool and tool_state in {"planned", "running", "completed", "failed", "blocked"}:
            tool_states[tool] = tool_state
        state = str(event.get("state") or "running")
        if state not in {"queued", "running", "completed", "failed", "blocked", "rejected"}:
            state = "running"
        active_tool = tool if tool_state == "running" else None
        parsed = MobileProgressEvent(
            sequence=len(events) + 1,
            at=datetime.fromisoformat(str(event.get("at") or datetime.now(UTC).isoformat())),
            state=state,
            stage=str(event.get("stage") or "worker")[:64],
            detail=" ".join(str(event.get("detail") or "Worker progress updated.").split())[:500],
            tool=tool,
            tool_state=tool_state,
            return_code=(int(event["return_code"]) if event.get("return_code") is not None else None),
            duration_ms=(int(event["duration_ms"]) if event.get("duration_ms") is not None else None),
            output_sha256=(
                str(event["output_sha256"]) if event.get("output_sha256") is not None else None
            ),
        )
        events.append(parsed)
        events = events[-_MAX_EVENTS:]
        snapshot = SignedMobileStaticProgress.create(
            job_id=job_id,
            state=state,
            active_tool=active_tool,
            tool_states=tool_states,
            events=tuple(events),
            result_summary=result_summary,
            updated_at=parsed.at,
            key=key,
        )
        self._atomic_write(path, snapshot.model_dump_json(indent=2) + "\n")
        return snapshot

    def finalize(
        self,
        *,
        job_id: str,
        success: bool,
        result_summary: dict[str, object],
        key: bytes,
    ) -> SignedMobileStaticProgress:
        source = self.processing / self._filename(job_id)
        if source.exists():
            current = self._load_path(source, key=key)
        else:
            current = SignedMobileStaticProgress.create(
                job_id=job_id,
                state="running",
                active_tool=None,
                tool_states={},
                events=(),
                result_summary=None,
                updated_at=datetime.now(UTC),
                key=key,
            )
        terminal_state: ProgressState = "completed" if success else "failed"
        snapshot = SignedMobileStaticProgress.create(
            job_id=job_id,
            state=terminal_state,
            active_tool=None,
            tool_states=current.tool_states,
            events=current.events,
            result_summary=result_summary,
            updated_at=datetime.now(UTC),
            key=key,
        )
        target_root = self.completed if success else self.failed
        target = target_root / self._filename(job_id)
        self._atomic_write(target, snapshot.model_dump_json(indent=2) + "\n")
        source.unlink(missing_ok=True)
        return snapshot

    def read(self, *, job_id: str, key: bytes) -> SignedMobileStaticProgress | None:
        filename = self._filename(job_id)
        for directory in (self.processing, self.completed, self.failed):
            path = directory / filename
            if path.is_file() and not path.is_symlink():
                return self._load_path(path, key=key)
        return None


__all__ = [
    "MobileProgressEvent",
    "MobileStaticProgressError",
    "MobileStaticProgressStore",
    "SignedMobileStaticProgress",
]
