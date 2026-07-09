"""Filesystem persistence with atomic manifests and hash-chained audit events."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import LoopIntegrityError, LoopNotFoundError
from vulnhunter.orchestration.models import (
    AuditEvent,
    EvaluationEvidence,
    HumanApprovalRecord,
    LearningRecord,
    LoopManifest,
    ReviewRecord,
    SecurityEvidence,
    normalize_actor_id,
)
from vulnhunter.security import redact_mapping, redact_text

try:
    import fcntl
except ImportError:  # pragma: no cover - VulnHunter currently targets Linux.
    fcntl = None

_ZERO_HASH = "0" * 64


_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _redact_audit_payload(payload: dict[str, object]) -> dict[str, object]:
    """Redact content without corrupting validated SHA-256 metadata."""
    safe_payload = redact_mapping(payload)

    for key, value in payload.items():
        if key != "sha256" and not key.endswith("_sha256"):
            continue
        if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
            raise LoopIntegrityError(f"Invalid SHA-256 audit metadata: {key}")
        safe_payload[key] = value.lower()

    return safe_payload


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")

    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class LoopStore:
    """Persist orchestration records outside the tracked source tree."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    @classmethod
    def from_path(cls, path: Path) -> LoopStore:
        return cls(path)

    def loop_directory(self, loop_id: str) -> Path:
        safe_id = self._safe_loop_id(loop_id)
        return self.root / safe_id

    def create(self, manifest: LoopManifest) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        directory = self.loop_directory(manifest.loop_id)
        try:
            directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError as exc:
            raise LoopIntegrityError(f"Loop {manifest.loop_id} already exists.") from exc

        (directory / "evidence").mkdir(mode=0o700)
        self._write_manifest(directory, manifest)
        (directory / "events.jsonl").touch(mode=0o600)

    def load(self, loop_id: str) -> LoopManifest:
        directory = self.loop_directory(loop_id)
        path = directory / "manifest.json"
        digest_path = directory / "manifest.sha256"
        if not path.is_file():
            raise LoopNotFoundError(f"Loop {loop_id} does not exist.")
        if not digest_path.is_file():
            raise LoopIntegrityError(f"Loop {loop_id} manifest digest is missing.")
        try:
            data = path.read_bytes()
            expected = digest_path.read_text(encoding="utf-8").strip()
            actual = hashlib.sha256(data).hexdigest()
            if expected != actual:
                raise LoopIntegrityError(f"Loop {loop_id} manifest failed integrity verification.")
            return LoopManifest.model_validate_json(data)
        except LoopIntegrityError:
            raise
        except (OSError, ValidationError) as exc:
            raise LoopIntegrityError(f"Loop {loop_id} manifest is unreadable or invalid.") from exc

    def save(self, manifest: LoopManifest) -> None:
        directory = self.loop_directory(manifest.loop_id)
        if not directory.is_dir():
            raise LoopNotFoundError(f"Loop {manifest.loop_id} does not exist.")
        self._write_manifest(directory, manifest)

    def list_manifests(self) -> tuple[LoopManifest, ...]:
        if not self.root.is_dir():
            return ()
        manifests: list[LoopManifest] = []
        for path in sorted(self.root.glob("*/manifest.json")):
            manifests.append(self.load(path.parent.name))
        manifests.sort(key=lambda item: item.created_at, reverse=True)
        return tuple(manifests)

    def append_event(
        self,
        loop_id: str,
        event_type: str,
        actor_id: str,
        payload: dict[str, object],
    ) -> AuditEvent:
        actor = normalize_actor_id(actor_id)
        directory = self.loop_directory(loop_id)
        event_path = directory / "events.jsonl"
        if not event_path.is_file():
            raise LoopNotFoundError(f"Loop {loop_id} does not exist.")

        safe_payload = _redact_audit_payload(payload)
        with self._locked(directory):
            events = self._read_events_unlocked(loop_id)
            previous_hash = events[-1].event_hash if events else _ZERO_HASH
            sequence = len(events) + 1
            created_at = datetime.now(UTC)
            unsigned = {
                "sequence": sequence,
                "loop_id": loop_id,
                "event_type": redact_text(event_type),
                "actor_id": actor,
                "created_at": created_at.isoformat(),
                "payload": safe_payload,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()
            event = AuditEvent(
                **unsigned,
                event_hash=event_hash,
            )

            with event_path.open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return event

    def read_events(self, loop_id: str) -> tuple[AuditEvent, ...]:
        directory = self.loop_directory(loop_id)
        with self._locked(directory):
            return self._read_events_unlocked(loop_id)

    def verify_event_chain(self, loop_id: str) -> tuple[AuditEvent, ...]:
        events = self.read_events(loop_id)
        previous_hash = _ZERO_HASH

        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence:
                raise LoopIntegrityError(f"Loop {loop_id} event sequence is not contiguous.")
            if event.previous_hash != previous_hash:
                raise LoopIntegrityError(f"Loop {loop_id} event chain has been altered.")
            unsigned = {
                "sequence": event.sequence,
                "loop_id": event.loop_id,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
                "created_at": event.created_at.isoformat(),
                "payload": event.payload,
                "previous_hash": event.previous_hash,
            }
            expected_hash = hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()
            if expected_hash != event.event_hash:
                raise LoopIntegrityError(
                    f"Loop {loop_id} event {event.sequence} failed integrity verification."
                )
            previous_hash = event.event_hash
        return events

    def verify_evidence_integrity(self, loop_id: str) -> tuple[AuditEvent, ...]:
        """Verify every evidence file referenced by the audit chain."""
        events = self.verify_event_chain(loop_id)
        directory = self.loop_directory(loop_id)
        for event in events:
            filename = event.payload.get("evidence_file")
            expected = event.payload.get("evidence_sha256")
            if filename is None and expected is None:
                continue
            if not isinstance(filename, str) or not isinstance(expected, str):
                raise LoopIntegrityError(
                    f"Loop {loop_id} event {event.sequence} has invalid evidence metadata."
                )
            path = directory / filename
            try:
                path.resolve().relative_to(directory.resolve())
            except ValueError as exc:
                raise LoopIntegrityError("Evidence path escapes the loop directory.") from exc
            if not path.is_file():
                raise LoopIntegrityError(f"Referenced evidence is missing: {filename}")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                raise LoopIntegrityError(
                    f"Referenced evidence failed integrity verification: {filename}"
                )
        return events

    def verify_integrity(self, loop_id: str) -> tuple[LoopManifest, tuple[AuditEvent, ...]]:
        """Verify the manifest, event chain, and referenced evidence."""
        manifest = self.load(loop_id)
        events = self.verify_evidence_integrity(loop_id)
        return manifest, events

    def save_evaluation(self, loop_id: str, evidence: EvaluationEvidence) -> Path:
        return self._save_evidence(
            loop_id,
            f"iteration-{evidence.iteration:03d}-evaluation.json",
            evidence.model_dump_json(indent=2) + "\n",
        )

    def save_security(self, loop_id: str, evidence: SecurityEvidence) -> Path:
        return self._save_evidence(
            loop_id,
            f"iteration-{evidence.iteration:03d}-security.json",
            evidence.model_dump_json(indent=2) + "\n",
        )

    def save_review(self, loop_id: str, record: ReviewRecord) -> Path:
        return self._save_evidence(
            loop_id,
            f"iteration-{record.iteration:03d}-review.json",
            record.model_dump_json(indent=2) + "\n",
        )

    def save_approval(self, loop_id: str, record: HumanApprovalRecord) -> Path:
        return self._save_evidence(
            loop_id,
            f"iteration-{record.iteration:03d}-approval.json",
            record.model_dump_json(indent=2) + "\n",
        )

    def save_learning(self, loop_id: str, record: LearningRecord) -> Path:
        directory = self.loop_directory(loop_id)
        lines = [
            f"# Learning Record — {loop_id}",
            "",
            f"- Iteration: `{record.iteration}`",
            f"- Recorded by: `{record.actor_id}`",
            f"- Recorded at: `{record.created_at.isoformat()}`",
            "",
            "## Summary",
            "",
            redact_text(record.summary),
            "",
            "## Known limitations",
            "",
        ]
        lines.extend(f"- {redact_text(item)}" for item in record.limitations)
        lines.extend(["", "## Documentation evidence", ""])
        lines.extend(f"- `{path}`" for path in record.documentation_paths)
        lines.append("")
        path = directory / "LEARNING.md"
        _atomic_write(path, "\n".join(lines))
        return path

    def load_latest_evaluation(self, loop_id: str) -> EvaluationEvidence:
        return self._load_latest(loop_id, "*-evaluation.json", EvaluationEvidence)

    def load_latest_security(self, loop_id: str) -> SecurityEvidence:
        return self._load_latest(loop_id, "*-security.json", SecurityEvidence)

    def load_latest_review(self, loop_id: str) -> ReviewRecord:
        return self._load_latest(loop_id, "*-review.json", ReviewRecord)

    def load_latest_approval(self, loop_id: str) -> HumanApprovalRecord:
        return self._load_latest(loop_id, "*-approval.json", HumanApprovalRecord)

    def _save_evidence(self, loop_id: str, filename: str, data: str) -> Path:
        directory = self.loop_directory(loop_id) / "evidence"
        if not directory.is_dir():
            raise LoopNotFoundError(f"Loop {loop_id} does not exist.")
        path = directory / filename
        if path.exists():
            raise LoopIntegrityError(f"Evidence already exists: {filename}")
        _atomic_write(path, data)
        return path

    def _load_latest(self, loop_id: str, pattern: str, model_type):
        directory = self.loop_directory(loop_id) / "evidence"
        matches = sorted(directory.glob(pattern))
        if not matches:
            raise LoopIntegrityError(f"Loop {loop_id} has no evidence matching {pattern}.")
        try:
            return model_type.model_validate_json(matches[-1].read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise LoopIntegrityError(
                f"Evidence is unreadable or invalid: {matches[-1].name}"
            ) from exc

    def _read_events_unlocked(self, loop_id: str) -> tuple[AuditEvent, ...]:
        path = self.loop_directory(loop_id) / "events.jsonl"
        events: list[AuditEvent] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    events.append(AuditEvent.model_validate_json(line))
        except (OSError, ValidationError) as exc:
            raise LoopIntegrityError(f"Loop {loop_id} event log is unreadable or invalid.") from exc
        return tuple(events)

    @contextmanager
    def _locked(self, directory: Path) -> Iterator[None]:
        if not directory.is_dir():
            raise LoopNotFoundError(f"Loop {directory.name} does not exist.")
        lock_path = directory / ".lock"
        with lock_path.open("a+") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _write_manifest(directory: Path, manifest: LoopManifest) -> None:
        data = manifest.model_dump_json(indent=2) + "\n"
        _atomic_write(directory / "manifest.json", data)
        digest = hashlib.sha256(data.encode("utf-8")).hexdigest() + "\n"
        _atomic_write(directory / "manifest.sha256", digest)

    @staticmethod
    def _safe_loop_id(loop_id: str) -> str:
        normalized = loop_id.strip()
        if not normalized or normalized in {".", ".."} or "/" in normalized or "\\" in normalized:
            raise LoopIntegrityError("Invalid loop ID.")
        return normalized
