"""Integrity-linked local storage for unattended manifests and runs."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import (
    UnattendedIntegrityError,
    UnattendedNotFoundError,
)
from vulnhunter.security import redact_mapping
from vulnhunter.unattended.models import (
    ApprovalRecord,
    AuditEvent,
    CommandEvidence,
    FailureRecord,
    PermissionManifest,
    RunRecord,
    normalize_actor_id,
)

_ZERO_HASH = "0" * 64


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class UnattendedStore:
    """Store immutable manifests, approvals, runs, evidence, and event chains."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    @classmethod
    def from_path(cls, path: Path) -> UnattendedStore:
        return cls(path)

    def manifest_directory(self, manifest_id: str) -> Path:
        return self.root / "manifests" / manifest_id

    def run_directory(self, run_id: str) -> Path:
        return self.root / "runs" / run_id

    def create_manifest(self, manifest: PermissionManifest) -> None:
        directory = self.manifest_directory(manifest.manifest_id)
        if directory.exists():
            raise UnattendedIntegrityError(f"Manifest {manifest.manifest_id} already exists.")
        directory.mkdir(parents=True, mode=0o700)
        _atomic_write(directory / "manifest.json", manifest.model_dump_json(indent=2).encode())
        _atomic_write(directory / "events.jsonl", b"")
        self.append_event(
            manifest.manifest_id,
            "manifest_created",
            manifest.created_by,
            {"manifest_sha256": self.manifest_sha256(manifest.manifest_id)},
        )

    def load_manifest(self, manifest_id: str) -> PermissionManifest:
        path = self.manifest_directory(manifest_id) / "manifest.json"
        try:
            return PermissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise UnattendedNotFoundError(f"Manifest {manifest_id} does not exist.") from exc
        except (OSError, ValidationError) as exc:
            raise UnattendedIntegrityError(f"Manifest {manifest_id} is invalid.") from exc

    def manifest_sha256(self, manifest_id: str) -> str:
        path = self.manifest_directory(manifest_id) / "manifest.json"
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise UnattendedNotFoundError(f"Manifest {manifest_id} does not exist.") from exc

    def save_approval(self, approval: ApprovalRecord) -> None:
        directory = self.manifest_directory(approval.manifest_id)
        if not directory.is_dir():
            raise UnattendedNotFoundError(f"Manifest {approval.manifest_id} does not exist.")
        path = directory / "approval.json"
        if path.exists():
            raise UnattendedIntegrityError("Manifest approval is immutable and already exists.")
        _atomic_write(path, approval.model_dump_json(indent=2).encode())
        self.append_event(
            approval.manifest_id,
            "manifest_approved",
            approval.approved_by,
            {
                "manifest_sha256": approval.manifest_sha256,
                "expires_at": approval.expires_at.isoformat(),
            },
        )

    def load_approval(self, manifest_id: str) -> ApprovalRecord:
        path = self.manifest_directory(manifest_id) / "approval.json"
        try:
            return ApprovalRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise UnattendedNotFoundError(f"Manifest {manifest_id} has no approval.") from exc
        except (OSError, ValidationError) as exc:
            raise UnattendedIntegrityError(f"Manifest {manifest_id} approval is invalid.") from exc

    def revoke_manifest(self, manifest_id: str, *, actor_id: str, reason: str) -> None:
        directory = self.manifest_directory(manifest_id)
        if not directory.is_dir():
            raise UnattendedNotFoundError(f"Manifest {manifest_id} does not exist.")
        path = directory / "revocation.json"
        if path.exists():
            raise UnattendedIntegrityError("Manifest is already revoked.")
        payload = {
            "manifest_id": manifest_id,
            "actor_id": normalize_actor_id(actor_id),
            "reason": reason,
            "revoked_at": datetime.now(UTC).isoformat(),
        }
        _atomic_write(path, (_canonical_json(payload) + "\n").encode())
        self.append_event(manifest_id, "manifest_revoked", actor_id, payload)

    def is_revoked(self, manifest_id: str) -> bool:
        return (self.manifest_directory(manifest_id) / "revocation.json").is_file()

    def create_run(self, run: RunRecord) -> None:
        directory = self.run_directory(run.run_id)
        if directory.exists():
            raise UnattendedIntegrityError(f"Run {run.run_id} already exists.")
        (directory / "evidence").mkdir(parents=True, mode=0o700)
        _atomic_write(directory / "run.json", run.model_dump_json(indent=2).encode())
        _atomic_write(directory / "events.jsonl", b"")
        _atomic_write(directory / "failures.jsonl", b"")
        self.append_event(
            run.run_id,
            "run_started",
            run.started_by,
            {"manifest_id": run.manifest_id, "manifest_sha256": run.manifest_sha256},
            run=True,
        )

    def load_run(self, run_id: str) -> RunRecord:
        path = self.run_directory(run_id) / "run.json"
        try:
            return RunRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise UnattendedNotFoundError(f"Run {run_id} does not exist.") from exc
        except (OSError, ValidationError) as exc:
            raise UnattendedIntegrityError(f"Run {run_id} is invalid.") from exc

    def save_run(self, run: RunRecord) -> None:
        directory = self.run_directory(run.run_id)
        if not directory.is_dir():
            raise UnattendedNotFoundError(f"Run {run.run_id} does not exist.")
        _atomic_write(directory / "run.json", run.model_dump_json(indent=2).encode())

    def save_command_evidence(self, evidence: CommandEvidence) -> Path:
        directory = self.run_directory(evidence.run_id) / "evidence"
        if not directory.is_dir():
            raise UnattendedNotFoundError(f"Run {evidence.run_id} does not exist.")
        path = (
            directory
            / f"command-{evidence.command_id.value}-{evidence.completed_at:%Y%m%dT%H%M%S%fZ}.json"
        )
        _atomic_write(path, evidence.model_dump_json(indent=2).encode())
        return path

    def command_evidence(self, run_id: str) -> tuple[CommandEvidence, ...]:
        directory = self.run_directory(run_id) / "evidence"
        records: list[CommandEvidence] = []
        try:
            for path in sorted(directory.glob("command-*.json")):
                records.append(
                    CommandEvidence.model_validate_json(path.read_text(encoding="utf-8"))
                )
        except (OSError, ValidationError) as exc:
            raise UnattendedIntegrityError(f"Run {run_id} command evidence is invalid.") from exc
        return tuple(records)

    def append_failure(self, failure: FailureRecord) -> None:
        path = self.run_directory(failure.run_id) / "failures.jsonl"
        if not path.is_file():
            raise UnattendedNotFoundError(f"Run {failure.run_id} does not exist.")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(failure.model_dump_json() + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def failures(self, run_id: str) -> tuple[FailureRecord, ...]:
        path = self.run_directory(run_id) / "failures.jsonl"
        records: list[FailureRecord] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    records.append(FailureRecord.model_validate_json(line))
        except FileNotFoundError as exc:
            raise UnattendedNotFoundError(f"Run {run_id} does not exist.") from exc
        except (OSError, ValidationError) as exc:
            raise UnattendedIntegrityError(f"Run {run_id} failures are invalid.") from exc
        return tuple(records)

    def append_event(
        self,
        subject_id: str,
        event_type: str,
        actor_id: str,
        payload: dict[str, object],
        *,
        run: bool = False,
    ) -> AuditEvent:
        directory = self.run_directory(subject_id) if run else self.manifest_directory(subject_id)
        path = directory / "events.jsonl"
        if not path.is_file():
            raise UnattendedNotFoundError(f"Control-plane subject {subject_id} does not exist.")
        with self._locked(directory):
            events = self._read_events(path)
            previous_hash = events[-1].event_hash if events else _ZERO_HASH
            unsigned = {
                "sequence": len(events) + 1,
                "subject_id": subject_id,
                "event_type": event_type,
                "actor_id": normalize_actor_id(actor_id),
                "created_at": datetime.now(UTC).isoformat(),
                "payload": redact_mapping(payload),
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(_canonical_json(unsigned).encode()).hexdigest()
            event = AuditEvent(**unsigned, event_hash=event_hash)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return event

    def read_events(self, subject_id: str, *, run: bool = False) -> tuple[AuditEvent, ...]:
        directory = self.run_directory(subject_id) if run else self.manifest_directory(subject_id)
        path = directory / "events.jsonl"
        if not path.is_file():
            raise UnattendedNotFoundError(f"Control-plane subject {subject_id} does not exist.")
        with self._locked(directory):
            return self._read_events(path)

    def verify_events(self, subject_id: str, *, run: bool = False) -> tuple[AuditEvent, ...]:
        events = self.read_events(subject_id, run=run)
        previous = _ZERO_HASH
        for sequence, event in enumerate(events, start=1):
            if event.sequence != sequence or event.previous_hash != previous:
                raise UnattendedIntegrityError("Control-plane event chain was altered.")
            unsigned = {
                "sequence": event.sequence,
                "subject_id": event.subject_id,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
                "created_at": event.created_at.isoformat(),
                "payload": event.payload,
                "previous_hash": event.previous_hash,
            }
            expected = hashlib.sha256(_canonical_json(unsigned).encode()).hexdigest()
            if expected != event.event_hash:
                raise UnattendedIntegrityError("Control-plane event integrity check failed.")
            previous = event.event_hash
        return events

    def verify_manifest(self, manifest_id: str) -> PermissionManifest:
        manifest = self.load_manifest(manifest_id)
        approval = self.load_approval(manifest_id)
        if approval.manifest_sha256 != self.manifest_sha256(manifest_id):
            raise UnattendedIntegrityError("Manifest changed after approval.")
        self.verify_events(manifest_id)
        return manifest

    def verify_run(self, run_id: str) -> RunRecord:
        run = self.load_run(run_id)
        manifest = self.verify_manifest(run.manifest_id)
        if run.manifest_sha256 != self.manifest_sha256(manifest.manifest_id):
            raise UnattendedIntegrityError("Run is no longer bound to its approved manifest.")
        self.verify_events(run_id, run=True)
        for evidence in self.command_evidence(run_id):
            unsigned = evidence.model_dump(mode="json", exclude={"evidence_sha256"})
            actual = hashlib.sha256(_canonical_json(unsigned).encode()).hexdigest()
            if actual != evidence.evidence_sha256:
                raise UnattendedIntegrityError("Command evidence failed integrity verification.")
        return run

    @staticmethod
    def _read_events(path: Path) -> tuple[AuditEvent, ...]:
        events: list[AuditEvent] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    events.append(AuditEvent.model_validate_json(line))
        except (OSError, ValidationError) as exc:
            raise UnattendedIntegrityError("Control-plane event log is invalid.") from exc
        return tuple(events)

    @contextmanager
    def _locked(self, directory: Path) -> Iterator[None]:
        lock = directory / ".lock"
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.close(descriptor)
            yield
        finally:
            lock.unlink(missing_ok=True)
