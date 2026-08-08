"""Production training packages bound to governed immutable dataset releases."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from vulnhunter import __version__
from vulnhunter.governance.models import canonical_sha256
from vulnhunter.governance.release_package import (
    CampaignReleasePackage,
    campaign_release_package_sha256,
)
from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.ml.dataset import dataset_sha256, to_training_example
from vulnhunter.ml.models import ModelArtifact, TrainingExample, TrainingLabel
from vulnhunter.ml.training import train_baseline, train_tuned
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.security import redact_text

ReleaseState = Literal["active", "withdrawn", "revoked", "superseded"]
ReleaseEventType = Literal["registered", "withdrawn", "revoked", "superseded"]
ExclusionReason = Literal["duplicate_same_label"]
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ZERO_HASH = "0" * 64


class ReleaseTrainingBoundaryError(RuntimeError):
    """A production release-to-training invariant failed closed."""


class TrainingReleaseEvent(BaseModel):
    """One append-only decision about a release's training eligibility."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    sequence: int = Field(ge=1)
    release_id: str = Field(min_length=8, max_length=80)
    campaign_id: str = Field(min_length=8, max_length=80)
    release_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_type: ReleaseEventType
    state: ReleaseState
    actor_id: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=1, max_length=2_000)
    superseded_by_release_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
    )
    occurred_at: datetime
    previous_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("release_id", "campaign_id", "superseded_by_release_id")
    @classmethod
    def stable_identifiers(cls, value: str | None) -> str | None:
        if value is not None and _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("release-training identifiers must be stable and path-safe")
        return value

    @field_validator("occurred_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("release-training event timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def event_matches_state(self) -> Self:
        expected = "active" if self.event_type == "registered" else self.event_type
        if self.state != expected:
            raise ValueError("release-training event type and state must agree")
        if self.state == "superseded":
            successor_missing = not self.superseded_by_release_id
            successor_same = self.superseded_by_release_id == self.release_id
            if successor_missing or successor_same:
                raise ValueError("superseded releases require a distinct successor release")
        elif self.superseded_by_release_id is not None:
            raise ValueError("only superseded releases may identify a successor")
        return self


def training_release_event_sha256(
    value: TrainingReleaseEvent | dict[str, object],
) -> str:
    return canonical_sha256(value, exclude={"event_sha256"})


class TrainingReleaseLedger:
    """Owner-private append-only training-eligibility ledger."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _path(self, release_id: str) -> Path:
        if _IDENTIFIER.fullmatch(release_id) is None:
            raise ReleaseTrainingBoundaryError("release ID is not a safe stable identifier")
        return self.root / f"{release_id}.jsonl"

    def events(self, release_id: str) -> tuple[TrainingReleaseEvent, ...]:
        path = self._path(release_id)
        if not path.exists():
            return ()
        if path.is_symlink():
            raise ReleaseTrainingBoundaryError("release-training ledger path is an unsafe symlink")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            events = tuple(TrainingReleaseEvent.model_validate_json(line) for line in lines if line)
        except (OSError, ValidationError) as exc:
            raise ReleaseTrainingBoundaryError(
                "release-training ledger is unavailable or invalid"
            ) from exc

        previous = _ZERO_HASH
        package_sha256: str | None = None
        for index, event in enumerate(events, start=1):
            if event.sequence != index:
                raise ReleaseTrainingBoundaryError("release-training ledger sequence is invalid")
            if event.release_id != release_id:
                raise ReleaseTrainingBoundaryError("release-training ledger key does not match")
            if event.previous_event_sha256 != previous:
                raise ReleaseTrainingBoundaryError("release-training ledger hash chain is invalid")
            if training_release_event_sha256(event) != event.event_sha256:
                raise ReleaseTrainingBoundaryError("release-training ledger event integrity failed")
            if package_sha256 is None:
                package_sha256 = event.release_package_sha256
            elif event.release_package_sha256 != package_sha256:
                raise ReleaseTrainingBoundaryError(
                    "release package identity changed inside its ledger"
                )
            previous = event.event_sha256

        if events and events[0].event_type != "registered":
            raise ReleaseTrainingBoundaryError(
                "release-training ledger must begin with registration"
            )
        if any(event.state != "active" for event in events[:-1]):
            raise ReleaseTrainingBoundaryError(
                "terminal release-training state cannot have later events"
            )
        return events

    def current(self, release_id: str) -> TrainingReleaseEvent | None:
        events = self.events(release_id)
        return events[-1] if events else None

    def require_active(
        self,
        package: CampaignReleasePackage,
    ) -> TrainingReleaseEvent:
        _verify_release_package_integrity(package)
        current = self.current(package.release_id)
        if current is None:
            raise ReleaseTrainingBoundaryError(
                "governed release is not registered for production training"
            )
        if current.release_package_sha256 != package.package_sha256:
            raise ReleaseTrainingBoundaryError("registered release package digest does not match")
        if current.release_manifest_sha256 != package.release_manifest_sha256:
            raise ReleaseTrainingBoundaryError("registered release manifest digest does not match")
        if current.state != "active":
            raise ReleaseTrainingBoundaryError(
                f"governed release is {current.state} and is not eligible "
                "for new production training"
            )
        return current

    def append(
        self,
        package: CampaignReleasePackage,
        *,
        state: ReleaseState,
        actor_id: str,
        reason: str,
        occurred_at: datetime,
        superseded_by_release_id: str | None = None,
    ) -> TrainingReleaseEvent:
        _verify_release_package_integrity(package)
        existing = self.events(package.release_id)
        if not existing:
            if state != "active":
                raise ReleaseTrainingBoundaryError(
                    "release must be registered active before transition"
                )
            event_type: ReleaseEventType = "registered"
            previous = _ZERO_HASH
            sequence = 1
        else:
            if existing[-1].state != "active":
                raise ReleaseTrainingBoundaryError(
                    "terminal release-training state cannot transition"
                )
            if state == "active":
                raise ReleaseTrainingBoundaryError("release is already registered active")
            event_type = state
            previous = existing[-1].event_sha256
            sequence = existing[-1].sequence + 1

        safe_reason = redact_text(reason).strip()[:2_000]
        if not safe_reason:
            raise ReleaseTrainingBoundaryError("release-training transition requires a reason")
        data: dict[str, object] = {
            "schema_version": 1,
            "sequence": sequence,
            "release_id": package.release_id,
            "campaign_id": package.campaign_id,
            "release_manifest_sha256": package.release_manifest_sha256,
            "release_package_sha256": package.package_sha256,
            "event_type": event_type,
            "state": state,
            "actor_id": actor_id,
            "reason": safe_reason,
            "superseded_by_release_id": superseded_by_release_id,
            "occurred_at": occurred_at,
            "previous_event_sha256": previous,
            "event_sha256": _ZERO_HASH,
        }
        data["event_sha256"] = training_release_event_sha256(data)
        event = TrainingReleaseEvent.model_validate(data)
        self._write(event)
        self.events(package.release_id)
        return event

    def _write(self, event: TrainingReleaseEvent) -> None:
        path = self._path(event.release_id)
        if path.exists() and path.is_symlink():
            raise ReleaseTrainingBoundaryError("release-training ledger path is an unsafe symlink")
        encoded = json.dumps(
            event.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)


def _now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ReleaseTrainingBoundaryError("release-training timestamps must include a timezone")
    return current.astimezone(UTC)


def _verify_release_package_integrity(package: CampaignReleasePackage) -> None:
    expected = campaign_release_package_sha256(package)
    if expected != package.package_sha256:
        raise ReleaseTrainingBoundaryError("campaign release package failed integrity verification")


def register_training_release(
    governance_store: GovernanceStore,
    ledger: TrainingReleaseLedger,
    package: CampaignReleasePackage,
    *,
    actor_id: str,
    actor_secret: str,
    reason: str = ("Approved governed release registered for production training eligibility."),
    now: datetime | None = None,
) -> TrainingReleaseEvent:
    """Register the exact current governed release for production training."""

    actor = authenticate_identity(
        governance_store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    governance_store.verify_integrity()
    release = governance_store.get_release(package.campaign_id)
    _verify_release_package_integrity(package)
    if release.release_id != package.release_id:
        raise ReleaseTrainingBoundaryError("release package does not match the governed release ID")
    if release.manifest_sha256 != package.release_manifest_sha256:
        raise ReleaseTrainingBoundaryError("release package does not match the governed manifest")
    return ledger.append(
        package,
        state="active",
        actor_id=actor.reviewer_id,
        reason=reason,
        occurred_at=_now(now),
    )


def transition_training_release(
    governance_store: GovernanceStore,
    ledger: TrainingReleaseLedger,
    package: CampaignReleasePackage,
    *,
    actor_id: str,
    actor_secret: str,
    state: Literal["withdrawn", "revoked", "superseded"],
    reason: str,
    successor: CampaignReleasePackage | None = None,
    now: datetime | None = None,
) -> TrainingReleaseEvent:
    """Transition a release and immediately block future production training."""

    actor = authenticate_identity(
        governance_store,
        actor_id,
        actor_secret,
        required_role="campaign_admin",
    )
    ledger.require_active(package)
    successor_id = None
    if state == "superseded":
        if successor is None:
            raise ReleaseTrainingBoundaryError("superseding a release requires its successor")
        ledger.require_active(successor)
        if successor.release_id == package.release_id:
            raise ReleaseTrainingBoundaryError("successor release must be distinct")
        successor_id = successor.release_id
    elif successor is not None:
        raise ReleaseTrainingBoundaryError("only superseded state accepts a successor release")
    return ledger.append(
        package,
        state=state,
        actor_id=actor.reviewer_id,
        reason=reason,
        occurred_at=_now(now),
        superseded_by_release_id=successor_id,
    )


class TrainingPackageApplication(BaseModel):
    """Grouping and authorisation lineage carried into production training."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_id: str
    application_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    application_family: str
    environment: str
    authorization_id: str
    authorization_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class TrainingPackageExample(BaseModel):
    """Canonical redacted example plus governed review provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    example: TrainingExample
    example_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_reference_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    application_id: str
    application_family: str
    environment: str
    review_resolution: Literal["consensus", "adjudicated"]
    assignment_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_attestation_sha256s: tuple[str, ...] = Field(min_length=2)


class TrainingPackageExclusion(BaseModel):
    """A released record omitted from canonical training content."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_reference_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: ExclusionReason


class ProductionTrainingPackage(BaseModel):
    """Content-addressed derivative of one active governed release."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    package_id: str = Field(min_length=8, max_length=100)
    source_release_id: str
    source_release_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_release_package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_id: str
    applications: tuple[TrainingPackageApplication, ...] = Field(min_length=1)
    examples: tuple[TrainingPackageExample, ...] = Field(min_length=1)
    excluded_records: tuple[TrainingPackageExclusion, ...] = ()
    dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    label_ontology_version: str = Field(min_length=1, max_length=100)
    redaction_policy_version: str = Field(min_length=1, max_length=100)
    privacy_classification: Literal["owner_private_redacted"] = "owner_private_redacted"
    permitted_tasks: tuple[str, ...] = Field(min_length=1)
    retention_policy: str = Field(min_length=1, max_length=500)
    generator_version: str
    source_commit: str
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("source_commit")
    @classmethod
    def commit_digest(cls, value: str) -> str:
        if _COMMIT.fullmatch(value) is None:
            raise ValueError("source_commit must be an exact SHA-1 or SHA-256 commit digest")
        return value

    @model_validator(mode="after")
    def unique_examples_and_groups(self) -> Self:
        refs = tuple(item.source_reference_sha256 for item in self.examples)
        if len(refs) != len(set(refs)):
            raise ValueError("training package source references must be unique")
        app_ids = tuple(item.application_id for item in self.applications)
        if len(app_ids) != len(set(app_ids)):
            raise ValueError("training package application IDs must be unique")
        return self


def production_training_package_sha256(
    value: ProductionTrainingPackage | dict[str, object],
) -> str:
    return canonical_sha256(value, exclude={"package_sha256"})


def _example_sha256(example: TrainingExample) -> str:
    return canonical_sha256(example.model_dump(mode="json"), exclude=set())


def _reference_sha256(reference: str) -> str:
    return hashlib.sha256(reference.encode("utf-8")).hexdigest()


def _parse_reference(reference: str) -> tuple[str, int]:
    database, marker, raw_id = reference.rpartition("#")
    if not marker or not database:
        raise ReleaseTrainingBoundaryError("released observation reference is malformed")
    try:
        observation_id = int(raw_id)
    except ValueError as exc:
        raise ReleaseTrainingBoundaryError("released observation reference has invalid ID") from exc
    if observation_id < 1:
        raise ReleaseTrainingBoundaryError("released observation reference has invalid ID")
    return database, observation_id


def _resolved_example(
    review,
    application,
    repository: ScanRepository,
) -> TrainingPackageExample:
    _, observation_id = _parse_reference(review.observation_reference)
    try:
        case = repository.get_review_case(observation_id)
    except ValueError as exc:
        raise ReleaseTrainingBoundaryError("released observation is unavailable") from exc
    if case.state != review.resolution_state:
        raise ReleaseTrainingBoundaryError("released review resolution changed after release")
    if case.effective_label != review.effective_label:
        raise ReleaseTrainingBoundaryError("released review label changed after release")
    try:
        example = to_training_example(case.observation)
    except ValueError as exc:
        raise ReleaseTrainingBoundaryError("released observation is not training eligible") from exc
    attestation_hashes = tuple(review.primary_attestation_record_sha256s)
    if review.adjudication_attestation_record_sha256 is not None:
        attestation_hashes += (review.adjudication_attestation_record_sha256,)
    return TrainingPackageExample(
        example=example,
        example_sha256=_example_sha256(example),
        source_reference_sha256=_reference_sha256(review.observation_reference),
        application_id=application.application_id,
        application_family=application.application_family,
        environment=application.environment,
        review_resolution=review.resolution_state,
        assignment_record_sha256=review.assignment_record_sha256,
        review_attestation_sha256s=attestation_hashes,
    )


def _canonicalize(
    resolved: list[TrainingPackageExample],
) -> tuple[
    tuple[TrainingPackageExample, ...],
    tuple[TrainingPackageExclusion, ...],
]:
    by_fingerprint: dict[str, list[TrainingPackageExample]] = {}
    for item in resolved:
        by_fingerprint.setdefault(item.example.fingerprint, []).append(item)

    canonical: list[TrainingPackageExample] = []
    excluded: list[TrainingPackageExclusion] = []
    for fingerprint, group in sorted(by_fingerprint.items()):
        labels: set[TrainingLabel] = {item.example.label for item in group}
        if len(labels) != 1:
            raise ReleaseTrainingBoundaryError(
                f"released fingerprint {fingerprint} has conflicting governed labels"
            )
        ordered = sorted(
            group,
            key=lambda item: (
                item.example.observation_id,
                item.source_reference_sha256,
            ),
        )
        canonical.append(ordered[0])
        excluded.extend(
            TrainingPackageExclusion(
                source_reference_sha256=item.source_reference_sha256,
                reason="duplicate_same_label",
            )
            for item in ordered[1:]
        )
    canonical.sort(
        key=lambda item: (
            item.example.observation_id,
            item.source_reference_sha256,
        )
    )
    excluded.sort(key=lambda item: item.source_reference_sha256)
    return tuple(canonical), tuple(excluded)


def build_production_training_package(
    release_package: CampaignReleasePackage,
    ledger: TrainingReleaseLedger,
    repositories: dict[str, ScanRepository],
    *,
    source_commit: str,
    label_ontology_version: str,
    redaction_policy_version: str,
    permitted_tasks: tuple[str, ...],
    retention_policy: str,
) -> ProductionTrainingPackage:
    """Derive canonical examples from one currently active governed release."""

    ledger.require_active(release_package)
    application_by_id = {item.application_id: item for item in release_package.applications}
    resolved: list[TrainingPackageExample] = []
    for review in release_package.reviews:
        application = application_by_id.get(review.application_id)
        if application is None:
            raise ReleaseTrainingBoundaryError("released review references an unknown application")
        database, _ = _parse_reference(review.observation_reference)
        repository = repositories.get(database)
        if repository is None:
            raise ReleaseTrainingBoundaryError("released observation repository is unavailable")
        resolved.append(_resolved_example(review, application, repository))

    examples, excluded = _canonicalize(resolved)
    if not examples:
        raise ReleaseTrainingBoundaryError(
            "governed release produced no canonical training examples"
        )

    safe_tasks = tuple(
        sorted({redact_text(item).strip() for item in permitted_tasks if item.strip()})
    )
    safe_retention = redact_text(retention_policy).strip()[:500]
    safe_label_version = redact_text(label_ontology_version).strip()[:100]
    safe_redaction_version = redact_text(redaction_policy_version).strip()[:100]
    if not all(
        (
            safe_tasks,
            safe_retention,
            safe_label_version,
            safe_redaction_version,
        )
    ):
        raise ReleaseTrainingBoundaryError("training package policy fields must be explicit")
    if _COMMIT.fullmatch(source_commit) is None:
        raise ReleaseTrainingBoundaryError("source_commit must be an exact SHA-1 or SHA-256 digest")

    applications = tuple(
        TrainingPackageApplication(
            application_id=item.application_id,
            application_record_sha256=item.application_record_sha256,
            application_family=item.application_family,
            environment=item.environment,
            authorization_id=item.authorization_id,
            authorization_record_sha256=item.authorization_record_sha256,
        )
        for item in sorted(
            release_package.applications,
            key=lambda current: current.application_id,
        )
    )
    canonical_examples = tuple(item.example for item in examples)
    base: dict[str, object] = {
        "schema_version": 1,
        "source_release_id": release_package.release_id,
        "source_release_manifest_sha256": (release_package.release_manifest_sha256),
        "source_release_package_sha256": release_package.package_sha256,
        "campaign_id": release_package.campaign_id,
        "applications": [item.model_dump(mode="json") for item in applications],
        "examples": [item.model_dump(mode="json") for item in examples],
        "excluded_records": [item.model_dump(mode="json") for item in excluded],
        "dataset_sha256": dataset_sha256(canonical_examples),
        "label_ontology_version": safe_label_version,
        "redaction_policy_version": safe_redaction_version,
        "privacy_classification": "owner_private_redacted",
        "permitted_tasks": safe_tasks,
        "retention_policy": safe_retention,
        "generator_version": __version__,
        "source_commit": source_commit,
    }
    identity = canonical_sha256(base, exclude=set())
    values = {
        **base,
        "package_id": f"training-package-{identity[:24]}",
        "package_sha256": _ZERO_HASH,
    }
    values["package_sha256"] = production_training_package_sha256(values)
    return ProductionTrainingPackage.model_validate(values)


def _verify_training_package(package: ProductionTrainingPackage) -> None:
    expected = production_training_package_sha256(package)
    if expected != package.package_sha256:
        raise ReleaseTrainingBoundaryError(
            "production training package failed integrity verification"
        )
    examples = tuple(item.example for item in package.examples)
    if dataset_sha256(examples) != package.dataset_sha256:
        raise ReleaseTrainingBoundaryError(
            "production training package dataset digest does not match"
        )


def _require_legacy_scan_identity_safety(
    package: ProductionTrainingPackage,
) -> None:
    """Fail until P3.3 replaces integer-only identity with hierarchical keys."""

    scan_apps: dict[int, set[str]] = {}
    observation_refs: dict[int, set[str]] = {}
    for item in package.examples:
        scan_apps.setdefault(item.example.scan_id, set()).add(item.application_id)
        observation_refs.setdefault(item.example.observation_id, set()).add(
            item.source_reference_sha256
        )
    if any(len(apps) > 1 for apps in scan_apps.values()):
        raise ReleaseTrainingBoundaryError(
            "production training is blocked because integer scan IDs overlap "
            "across applications; P3.3 hierarchical grouping is required"
        )
    if any(len(refs) > 1 for refs in observation_refs.values()):
        raise ReleaseTrainingBoundaryError(
            "production training is blocked because observation IDs overlap "
            "across released sources; P3.3 hierarchical identity is required"
        )


class GovernedModelCandidate(BaseModel):
    """Model bytes plus proof of the governed production training boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    training_mode: Literal["production_candidate"] = "production_candidate"
    training_package_id: str
    training_package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_release_id: str
    source_release_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model: ModelArtifact
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def governed_model_candidate_sha256(
    value: GovernedModelCandidate | dict[str, object],
) -> str:
    return canonical_sha256(value, exclude={"candidate_sha256"})


def _candidate(
    package: ProductionTrainingPackage,
    artifact: ModelArtifact,
) -> GovernedModelCandidate:
    if artifact.dataset_sha256 != package.dataset_sha256:
        raise ReleaseTrainingBoundaryError(
            "trained artifact dataset does not match governed package"
        )
    data: dict[str, object] = {
        "schema_version": 1,
        "training_mode": "production_candidate",
        "training_package_id": package.package_id,
        "training_package_sha256": package.package_sha256,
        "source_release_id": package.source_release_id,
        "source_release_manifest_sha256": (package.source_release_manifest_sha256),
        "model": artifact,
        "candidate_sha256": _ZERO_HASH,
    }
    data["candidate_sha256"] = governed_model_candidate_sha256(data)
    return GovernedModelCandidate.model_validate(data)


def _validate_training_source(
    package: ProductionTrainingPackage,
    ledger: TrainingReleaseLedger,
    release_package: CampaignReleasePackage,
) -> None:
    _verify_training_package(package)
    if package.source_release_id != release_package.release_id:
        raise ReleaseTrainingBoundaryError("training package release identity does not match")
    if package.source_release_package_sha256 != release_package.package_sha256:
        raise ReleaseTrainingBoundaryError("training package release digest does not match")
    ledger.require_active(release_package)
    _require_legacy_scan_identity_safety(package)


def train_production_baseline(
    package: ProductionTrainingPackage,
    ledger: TrainingReleaseLedger,
    release_package: CampaignReleasePackage,
    **training_options,
) -> GovernedModelCandidate:
    """Train the baseline only while the source release remains active."""

    _validate_training_source(package, ledger, release_package)
    examples = tuple(item.example for item in package.examples)
    artifact = train_baseline(examples, **training_options)
    return _candidate(package, artifact)


def train_production_tuned(
    package: ProductionTrainingPackage,
    ledger: TrainingReleaseLedger,
    release_package: CampaignReleasePackage,
    **training_options,
) -> GovernedModelCandidate:
    """Tune the baseline family only while the source release remains active."""

    _validate_training_source(package, ledger, release_package)
    examples = tuple(item.example for item in package.examples)
    artifact = train_tuned(examples, **training_options)
    return _candidate(package, artifact)


__all__ = [
    "GovernedModelCandidate",
    "ProductionTrainingPackage",
    "ReleaseTrainingBoundaryError",
    "TrainingPackageApplication",
    "TrainingPackageExample",
    "TrainingPackageExclusion",
    "TrainingReleaseEvent",
    "TrainingReleaseLedger",
    "build_production_training_package",
    "governed_model_candidate_sha256",
    "production_training_package_sha256",
    "register_training_release",
    "train_production_baseline",
    "train_production_tuned",
    "training_release_event_sha256",
    "transition_training_release",
]
