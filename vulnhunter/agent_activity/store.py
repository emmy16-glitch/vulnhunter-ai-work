"""Append-only hash-chained persistence for bounded-agent activity events."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from vulnhunter.agent_activity.models import (
    ActivityEvent,
    ActivityEventDraft,
    ActivityIntegrityResult,
)


class ActivityStoreError(RuntimeError):
    """Base error for activity stream persistence."""


class ActivityIntegrityError(ActivityStoreError):
    """Raised when persisted activity evidence fails integrity validation."""


_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def _hashable_payload(payload: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key not in {"event_id", "event_sha256"}}


def _event_sha256(payload: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(_hashable_payload(payload))).hexdigest()


class AppendOnlyActivityStore:
    """A local append-only JSONL event store with a per-run integrity chain."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, run_id: str) -> Path:
        if not _SAFE_RUN_ID.fullmatch(run_id):
            raise ActivityStoreError("run_id contains unsafe path characters")
        path = self.root / f"{run_id}.jsonl"
        if path.exists() and path.is_symlink():
            raise ActivityStoreError("activity stream must not be a symbolic link")
        return path

    @staticmethod
    def _load_locked(handle: TextIO, run_id: str) -> list[ActivityEvent]:
        handle.seek(0)
        events: list[ActivityEvent] = []
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                event = ActivityEvent.model_validate(payload)
            except (json.JSONDecodeError, ValidationError) as exc:
                raise ActivityIntegrityError(
                    f"invalid activity event at line {line_number}: {exc}"
                ) from exc
            if event.run_id != run_id:
                raise ActivityIntegrityError(f"run mismatch at sequence {event.sequence}")
            events.append(event)
        errors = AppendOnlyActivityStore._integrity_errors(events)
        if errors:
            raise ActivityIntegrityError("; ".join(errors))
        return events

    @staticmethod
    def _integrity_errors(events: list[ActivityEvent]) -> list[str]:
        errors: list[str] = []
        previous_hash: str | None = None
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence:
                errors.append(
                    f"non-contiguous sequence: expected {expected_sequence}, got {event.sequence}"
                )
            if event.previous_event_sha256 != previous_hash:
                errors.append(f"previous hash mismatch at sequence {event.sequence}")
            payload = event.model_dump(mode="json")
            expected_hash = _event_sha256(payload)
            if event.event_sha256 != expected_hash:
                errors.append(f"event hash mismatch at sequence {event.sequence}")
            expected_id = f"evt_{expected_hash[:24]}"
            if event.event_id != expected_id:
                errors.append(f"event id mismatch at sequence {event.sequence}")
            previous_hash = event.event_sha256
        return errors

    def append(self, draft: ActivityEventDraft) -> ActivityEvent:
        """Append one immutable event after validating the complete existing chain."""
        path = self._path_for(draft.run_id)
        with path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                events = self._load_locked(handle, draft.run_id)
                previous_hash = events[-1].event_sha256 if events else None
                payload = draft.model_dump(mode="json")
                payload.update(
                    {
                        "sequence": len(events) + 1,
                        "previous_event_sha256": previous_hash,
                    }
                )
                event_hash = _event_sha256(payload)
                payload.update(
                    {
                        "event_id": f"evt_{event_hash[:24]}",
                        "event_sha256": event_hash,
                    }
                )
                event = ActivityEvent.model_validate(payload)
                handle.seek(0, os.SEEK_END)
                handle.write(
                    json.dumps(
                        event.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
                return event
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def read_after(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 200,
    ) -> tuple[ActivityEvent, ...]:
        """Read an ordered page without mutating the event stream."""
        if after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000")
        path = self._path_for(run_id)
        if not path.exists():
            return ()
        with path.open("r", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            try:
                events = self._load_locked(handle, run_id)
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return tuple(event for event in events if event.sequence > after_sequence)[:limit]

    def verify(self, run_id: str) -> ActivityIntegrityResult:
        """Verify one stream without altering persisted evidence."""
        path = self._path_for(run_id)
        if not path.exists():
            return ActivityIntegrityResult(
                run_id=run_id,
                valid=True,
                event_count=0,
                last_sequence=0,
                last_event_sha256=None,
                errors=(),
            )
        try:
            with path.open("r", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
                try:
                    events = self._load_locked(handle, run_id)
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except ActivityIntegrityError as exc:
            return ActivityIntegrityResult(
                run_id=run_id,
                valid=False,
                event_count=0,
                last_sequence=0,
                last_event_sha256=None,
                errors=(str(exc),),
            )
        last = events[-1] if events else None
        return ActivityIntegrityResult(
            run_id=run_id,
            valid=True,
            event_count=len(events),
            last_sequence=last.sequence if last else 0,
            last_event_sha256=last.event_sha256 if last else None,
            errors=(),
        )
