"""Atomic experiment persistence with integrity-linked evidence and events."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import ResearchIntegrityError, ResearchNotFoundError
from vulnhunter.research.boundaries import policy_sha256, protected_snapshot_sha256
from vulnhunter.research.models import (
    EvaluatorPolicy,
    ExperimentDecision,
    ExperimentEvaluation,
    ExperimentManifest,
    MetaAnalysis,
    ProtectedSnapshot,
    RecordedMetricReport,
    ResearchEvent,
    SearchPolicy,
    normalize_actor_id,
)
from vulnhunter.security import redact_mapping, redact_text

try:
    import fcntl
except ImportError:  # pragma: no cover - VulnHunter currently targets Linux.
    fcntl = None

_ZERO_HASH = "0" * 64


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


class ResearchStore:
    """Persist experiment state outside the candidate worktree."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    @classmethod
    def from_path(cls, path: Path) -> ResearchStore:
        return cls(path)

    def experiment_directory(self, experiment_id: str) -> Path:
        safe_id = self._safe_id(experiment_id)
        return self.root / safe_id

    def create(
        self,
        manifest: ExperimentManifest,
        *,
        policy: EvaluatorPolicy,
        snapshot: ProtectedSnapshot,
    ) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        directory = self.experiment_directory(manifest.experiment_id)
        try:
            directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError as exc:
            raise ResearchIntegrityError(
                f"Experiment {manifest.experiment_id} already exists."
            ) from exc
        (directory / "evidence").mkdir(mode=0o700)
        self._write_manifest(directory, manifest)
        self._write_model(directory / "policy.json", policy)
        self._write_model(directory / "protected-snapshot.json", snapshot)
        (directory / "events.jsonl").touch(mode=0o600)

    def load(self, experiment_id: str) -> ExperimentManifest:
        directory = self.experiment_directory(experiment_id)
        return self._read_model_with_digest(
            directory / "manifest.json",
            directory / "manifest.sha256",
            ExperimentManifest,
            label="experiment manifest",
        )

    def save(self, manifest: ExperimentManifest) -> None:
        directory = self.experiment_directory(manifest.experiment_id)
        if not directory.is_dir():
            raise ResearchNotFoundError(f"Experiment {manifest.experiment_id} does not exist.")
        self._write_manifest(directory, manifest)

    def list_manifests(self) -> tuple[ExperimentManifest, ...]:
        if not self.root.is_dir():
            return ()
        manifests = [self.load(path.parent.name) for path in self.root.glob("*/manifest.json")]
        manifests.sort(key=lambda item: item.created_at, reverse=True)
        return tuple(manifests)

    def load_policy(self, experiment_id: str) -> EvaluatorPolicy:
        path = self.experiment_directory(experiment_id) / "policy.json"
        return self._read_model(path, EvaluatorPolicy, "evaluator policy")

    def load_snapshot(self, experiment_id: str) -> ProtectedSnapshot:
        path = self.experiment_directory(experiment_id) / "protected-snapshot.json"
        return self._read_model(path, ProtectedSnapshot, "protected snapshot")

    def save_baseline_report(self, experiment_id: str, report: RecordedMetricReport) -> Path:
        return self._save_unique_model(experiment_id, "baseline-report.json", report)

    def load_baseline_report(self, experiment_id: str) -> RecordedMetricReport:
        return self._read_evidence_model(
            experiment_id, "baseline-report.json", RecordedMetricReport
        )

    def save_candidate_report(self, experiment_id: str, report: RecordedMetricReport) -> Path:
        return self._save_unique_model(experiment_id, "candidate-report.json", report)

    def load_candidate_report(self, experiment_id: str) -> RecordedMetricReport:
        return self._read_evidence_model(
            experiment_id, "candidate-report.json", RecordedMetricReport
        )

    def save_evaluation(self, experiment_id: str, evaluation: ExperimentEvaluation) -> Path:
        return self._save_unique_model(experiment_id, "evaluation.json", evaluation)

    def load_evaluation(self, experiment_id: str) -> ExperimentEvaluation:
        return self._read_evidence_model(experiment_id, "evaluation.json", ExperimentEvaluation)

    def save_decision(self, experiment_id: str, decision: ExperimentDecision) -> Path:
        return self._save_unique_model(experiment_id, "decision.json", decision)

    def load_decision(self, experiment_id: str) -> ExperimentDecision:
        return self._read_evidence_model(experiment_id, "decision.json", ExperimentDecision)

    def save_patch(self, experiment_id: str, patch: bytes) -> Path:
        path = self.experiment_directory(experiment_id) / "evidence" / "candidate.patch"
        if path.exists():
            raise ResearchIntegrityError("Candidate patch evidence already exists.")
        _atomic_write_bytes(path, patch)
        return path

    def save_meta_analysis(self, analysis: MetaAnalysis) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        directory = self.root / "meta"
        directory.mkdir(mode=0o700, exist_ok=True)
        name = f"analysis-{analysis.created_at:%Y%m%dT%H%M%S%fZ}.json"
        path = directory / name
        self._write_model(path, analysis)
        return path

    def save_search_policy(self, policy: SearchPolicy) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / "search-policy.json"
        data = policy.model_dump_json(indent=2) + "\n"
        _atomic_write_text(path, data)
        _atomic_write_text(
            self.root / "search-policy.sha256",
            hashlib.sha256(data.encode("utf-8")).hexdigest() + "\n",
        )
        return path

    def load_search_policy(self) -> SearchPolicy | None:
        path = self.root / "search-policy.json"
        if not path.is_file():
            return None
        digest_path = self.root / "search-policy.sha256"
        return self._read_model_with_digest(
            path,
            digest_path,
            SearchPolicy,
            label="search policy",
        )

    def append_event(
        self,
        experiment_id: str,
        event_type: str,
        actor_id: str,
        payload: dict[str, object],
    ) -> ResearchEvent:
        actor = normalize_actor_id(actor_id)
        directory = self.experiment_directory(experiment_id)
        event_path = directory / "events.jsonl"
        if not event_path.is_file():
            raise ResearchNotFoundError(f"Experiment {experiment_id} does not exist.")

        safe_payload = redact_mapping(payload)
        with self._locked(directory):
            events = self._read_events_unlocked(experiment_id)
            previous_hash = events[-1].event_hash if events else _ZERO_HASH
            sequence = len(events) + 1
            created_at = datetime.now(UTC)
            unsigned = {
                "sequence": sequence,
                "experiment_id": experiment_id,
                "event_type": redact_text(event_type),
                "actor_id": actor,
                "created_at": created_at.isoformat(),
                "payload": safe_payload,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()
            event = ResearchEvent(**unsigned, event_hash=event_hash)
            with event_path.open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return event

    def read_events(self, experiment_id: str) -> tuple[ResearchEvent, ...]:
        directory = self.experiment_directory(experiment_id)
        with self._locked(directory):
            return self._read_events_unlocked(experiment_id)

    def verify_integrity(
        self, experiment_id: str
    ) -> tuple[ExperimentManifest, tuple[ResearchEvent, ...]]:
        manifest = self.load(experiment_id)
        policy = self.load_policy(experiment_id)
        snapshot = self.load_snapshot(experiment_id)
        if policy_sha256(policy) != manifest.policy_sha256:
            raise ResearchIntegrityError(
                "Evaluator policy does not match the manifest policy hash."
            )
        if protected_snapshot_sha256(snapshot) != manifest.protected_snapshot_sha256:
            raise ResearchIntegrityError(
                "Protected snapshot does not match the manifest snapshot hash."
            )
        if snapshot.policy_sha256 != manifest.policy_sha256:
            raise ResearchIntegrityError(
                "Protected snapshot is bound to a different evaluator policy."
            )
        if snapshot.repository_commit != manifest.baseline_commit:
            raise ResearchIntegrityError(
                "Protected snapshot is bound to a different baseline commit."
            )
        events = self.read_events(experiment_id)
        previous_hash = _ZERO_HASH
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence or event.previous_hash != previous_hash:
                raise ResearchIntegrityError("Experiment event chain has been altered.")
            unsigned = {
                "sequence": event.sequence,
                "experiment_id": event.experiment_id,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
                "created_at": event.created_at.isoformat(),
                "payload": event.payload,
                "previous_hash": event.previous_hash,
            }
            expected = hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()
            if event.event_hash != expected:
                raise ResearchIntegrityError(
                    f"Experiment event {event.sequence} failed integrity verification."
                )
            evidence_file = event.payload.get("evidence_file")
            evidence_hash = event.payload.get("evidence_sha256")
            if evidence_file is not None or evidence_hash is not None:
                if not isinstance(evidence_file, str) or not isinstance(evidence_hash, str):
                    raise ResearchIntegrityError("Invalid evidence metadata in event chain.")
                path = self.experiment_directory(experiment_id) / evidence_file
                try:
                    path.resolve().relative_to(self.experiment_directory(experiment_id).resolve())
                except ValueError as exc:
                    raise ResearchIntegrityError("Evidence path escapes experiment store.") from exc
                if not path.is_file():
                    raise ResearchIntegrityError(f"Referenced evidence is missing: {evidence_file}")
                if hashlib.sha256(path.read_bytes()).hexdigest() != evidence_hash:
                    raise ResearchIntegrityError(
                        f"Referenced evidence failed integrity verification: {evidence_file}"
                    )
            previous_hash = event.event_hash
        return manifest, events

    def evidence_relative_path(self, experiment_id: str, path: Path) -> str:
        return str(path.resolve().relative_to(self.experiment_directory(experiment_id)))

    @staticmethod
    def sha256_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _save_unique_model(self, experiment_id: str, name: str, model) -> Path:
        path = self.experiment_directory(experiment_id) / "evidence" / name
        if path.exists():
            raise ResearchIntegrityError(f"Evidence already exists: {name}")
        self._write_model(path, model)
        return path

    def _read_evidence_model(self, experiment_id: str, name: str, model_type):
        path = self.experiment_directory(experiment_id) / "evidence" / name
        return self._read_model(path, model_type, name)

    @staticmethod
    def _write_model(path: Path, model) -> None:
        _atomic_write_text(path, model.model_dump_json(indent=2) + "\n")

    @staticmethod
    def _write_manifest(directory: Path, manifest: ExperimentManifest) -> None:
        data = manifest.model_dump_json(indent=2) + "\n"
        _atomic_write_text(directory / "manifest.json", data)
        _atomic_write_text(
            directory / "manifest.sha256",
            hashlib.sha256(data.encode("utf-8")).hexdigest() + "\n",
        )

    @staticmethod
    def _read_model(path: Path, model_type, label: str):
        if not path.is_file():
            raise ResearchIntegrityError(f"Missing {label}: {path.name}")
        try:
            return model_type.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise ResearchIntegrityError(f"Unreadable or invalid {label}.") from exc

    @classmethod
    def _read_model_with_digest(
        cls,
        path: Path,
        digest_path: Path,
        model_type,
        *,
        label: str,
    ):
        if not path.is_file():
            raise ResearchNotFoundError(f"Missing {label}.")
        if not digest_path.is_file():
            raise ResearchIntegrityError(f"Missing digest for {label}.")
        data = path.read_bytes()
        expected = digest_path.read_text(encoding="utf-8").strip()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ResearchIntegrityError(f"{label.capitalize()} failed integrity verification.")
        try:
            return model_type.model_validate_json(data)
        except ValidationError as exc:
            raise ResearchIntegrityError(f"Invalid {label}.") from exc

    def _read_events_unlocked(self, experiment_id: str) -> tuple[ResearchEvent, ...]:
        path = self.experiment_directory(experiment_id) / "events.jsonl"
        if not path.is_file():
            raise ResearchNotFoundError(f"Experiment {experiment_id} does not exist.")
        events: list[ResearchEvent] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    events.append(ResearchEvent.model_validate_json(line))
        except (OSError, ValidationError) as exc:
            raise ResearchIntegrityError("Experiment event log is invalid.") from exc
        return tuple(events)

    @contextmanager
    def _locked(self, directory: Path) -> Iterator[None]:
        if not directory.is_dir():
            raise ResearchNotFoundError(f"Experiment {directory.name} does not exist.")
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
    def _safe_id(experiment_id: str) -> str:
        normalized = experiment_id.strip()
        if not normalized or normalized in {".", ".."} or "/" in normalized or "\\" in normalized:
            raise ResearchIntegrityError("Invalid experiment ID.")
        return normalized
