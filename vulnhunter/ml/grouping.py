"""Hierarchical application identity and stable production ML partitioning."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vulnhunter.governance.models import canonical_sha256
from vulnhunter.governance.release_package import CampaignReleasePackage
from vulnhunter.ml.dataset import dataset_sha256
from vulnhunter.ml.models import ModelArtifact, TrainingExample
from vulnhunter.ml.release_training import (
    ProductionTrainingPackage,
    ReleaseTrainingBoundaryError,
    TrainingReleaseLedger,
    production_training_package_sha256,
)
from vulnhunter.ml.training import train_baseline, train_tuned
from vulnhunter.security import redact_text

PartitionName = Literal[
    "development_training",
    "development_calibration",
    "external_holdout",
]
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_ZERO_HASH = "0" * 64
_MAX_SURROGATE_ID = 2_000_000_000


class GroupingBoundaryError(RuntimeError):
    """A hierarchical grouping or partition invariant failed closed."""


def _stable_id(namespace: str, value: str) -> str:
    normalized = " ".join(redact_text(value).strip().lower().split())
    if not normalized:
        raise GroupingBoundaryError(f"{namespace} identity must be explicit")
    digest = hashlib.sha256(f"{namespace}\0{normalized}".encode()).hexdigest()
    return f"{namespace}-{digest[:24]}"


def _aware(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise GroupingBoundaryError("partition timestamps must include a timezone")
    return current.astimezone(UTC)


class HierarchicalApplicationIdentity(BaseModel):
    """Stable grouping keys for one governed application lineage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_family_id: str
    application_instance_id: str
    deployment_environment_id: str
    repository_id: str | None = None
    repository_revision: str | None = None
    artifact_digest: str | None = None

    @field_validator(
        "application_family_id",
        "application_instance_id",
        "deployment_environment_id",
        "repository_id",
    )
    @classmethod
    def stable_identifier(cls, value: str | None) -> str | None:
        if value is not None and _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("hierarchical grouping identifiers must be stable and path-safe")
        return value

    @field_validator("artifact_digest")
    @classmethod
    def artifact_sha(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("artifact_digest must be a SHA-256 digest")
        return value


def application_identity(application) -> HierarchicalApplicationIdentity:
    """Derive stable IDs from governed application metadata without using scan IDs."""

    return HierarchicalApplicationIdentity(
        application_family_id=_stable_id("family", application.application_family),
        application_instance_id=_stable_id("instance", application.application_id),
        deployment_environment_id=_stable_id(
            "environment", f"{application.application_id}:{application.environment}"
        ),
    )


class HierarchicalExampleIdentity(BaseModel):
    """One example's complete available grouping hierarchy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_family_id: str
    application_instance_id: str
    deployment_environment_id: str
    authorization_id: str
    campaign_id: str
    scan_key: str
    observation_key: str
    legacy_scan_id: int = Field(ge=1)
    legacy_observation_id: int = Field(ge=1)


class PartitionAssignmentEvent(BaseModel):
    """Append-only assignment of one application family to one partition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    sequence: int = Field(ge=1)
    programme_id: str
    grouping_policy_version: str = Field(min_length=1, max_length=100)
    application_family_id: str
    partition: PartitionName
    actor_id: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=1, max_length=2_000)
    supersedes_programme_id: str | None = None
    occurred_at: datetime
    previous_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("programme_id", "application_family_id", "supersedes_programme_id")
    @classmethod
    def identifiers(cls, value: str | None) -> str | None:
        if value is not None and _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("partition identifiers must be stable and path-safe")
        return value

    @field_validator("occurred_at")
    @classmethod
    def timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("partition event timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def reset_only_on_first_event(self) -> Self:
        if self.sequence != 1 and self.supersedes_programme_id is not None:
            raise ValueError("only the first partition event may declare a programme reset")
        if self.supersedes_programme_id == self.programme_id:
            raise ValueError("a partition programme cannot supersede itself")
        return self


def partition_event_sha256(value: PartitionAssignmentEvent | dict[str, object]) -> str:
    return canonical_sha256(value, exclude={"event_sha256"})


class PartitionRegistry:
    """Owner-private immutable application-family partition assignments."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _path(self, programme_id: str) -> Path:
        if _IDENTIFIER.fullmatch(programme_id) is None:
            raise GroupingBoundaryError("partition programme ID is not path-safe")
        return self.root / f"{programme_id}.jsonl"

    def events(self, programme_id: str) -> tuple[PartitionAssignmentEvent, ...]:
        path = self._path(programme_id)
        if not path.exists():
            return ()
        if path.is_symlink():
            raise GroupingBoundaryError("partition registry path is an unsafe symlink")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            events = tuple(
                PartitionAssignmentEvent.model_validate_json(line) for line in lines if line
            )
        except (OSError, ValidationError) as exc:
            raise GroupingBoundaryError("partition registry is unavailable or invalid") from exc

        previous = _ZERO_HASH
        families: set[str] = set()
        policy: str | None = None
        supersedes: str | None = None
        for index, event in enumerate(events, start=1):
            if event.sequence != index or event.programme_id != programme_id:
                raise GroupingBoundaryError("partition registry sequence or key is invalid")
            if event.previous_event_sha256 != previous:
                raise GroupingBoundaryError("partition registry hash chain is invalid")
            if partition_event_sha256(event) != event.event_sha256:
                raise GroupingBoundaryError("partition registry event integrity failed")
            if event.application_family_id in families:
                raise GroupingBoundaryError(
                    "application family appears more than once in a programme"
                )
            families.add(event.application_family_id)
            if policy is None:
                policy = event.grouping_policy_version
                supersedes = event.supersedes_programme_id
            elif event.grouping_policy_version != policy:
                raise GroupingBoundaryError("grouping policy changed inside one programme")
            elif event.supersedes_programme_id != supersedes:
                raise GroupingBoundaryError("partition reset lineage changed inside one programme")
            previous = event.event_sha256
        return events

    def assignments(self, programme_id: str) -> dict[str, PartitionName]:
        return {event.application_family_id: event.partition for event in self.events(programme_id)}

    def assign_family(
        self,
        *,
        programme_id: str,
        grouping_policy_version: str,
        application_family_id: str,
        partition: PartitionName,
        actor_id: str,
        reason: str,
        supersedes_programme_id: str | None = None,
        now: datetime | None = None,
    ) -> PartitionAssignmentEvent:
        existing = self.events(programme_id)
        by_family = {event.application_family_id: event for event in existing}
        prior = by_family.get(application_family_id)
        if prior is not None:
            if prior.partition == partition:
                return prior
            raise GroupingBoundaryError(
                "application family partition is frozen for this evaluation programme"
            )
        if existing:
            first = existing[0]
            if grouping_policy_version != first.grouping_policy_version:
                raise GroupingBoundaryError("grouping policy cannot change inside one programme")
            if supersedes_programme_id != first.supersedes_programme_id:
                raise GroupingBoundaryError("programme reset lineage must remain stable")
        elif supersedes_programme_id is not None:
            if not self.events(supersedes_programme_id):
                raise GroupingBoundaryError("superseded partition programme does not exist")

        safe_reason = redact_text(reason).strip()[:2_000]
        if not safe_reason:
            raise GroupingBoundaryError("partition assignment requires a reason")
        previous = existing[-1].event_sha256 if existing else _ZERO_HASH
        values: dict[str, object] = {
            "schema_version": 1,
            "sequence": len(existing) + 1,
            "programme_id": programme_id,
            "grouping_policy_version": redact_text(grouping_policy_version).strip()[:100],
            "application_family_id": application_family_id,
            "partition": partition,
            "actor_id": actor_id,
            "reason": safe_reason,
            "supersedes_programme_id": supersedes_programme_id,
            "occurred_at": _aware(now),
            "previous_event_sha256": previous,
            "event_sha256": _ZERO_HASH,
        }
        if not values["grouping_policy_version"]:
            raise GroupingBoundaryError("grouping policy version must be explicit")
        values["event_sha256"] = partition_event_sha256(values)
        event = PartitionAssignmentEvent.model_validate(values)
        self._write(event)
        self.events(programme_id)
        return event

    def _write(self, event: PartitionAssignmentEvent) -> None:
        path = self._path(event.programme_id)
        if path.exists() and path.is_symlink():
            raise GroupingBoundaryError("partition registry path is an unsafe symlink")
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


class PartitionedTrainingExample(BaseModel):
    """Governed example with stable hierarchy and frozen partition assignment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_reference_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    partition: PartitionName
    identity: HierarchicalExampleIdentity
    example: TrainingExample


class PartitionedProductionDataset(BaseModel):
    """One release projected through an immutable family-level evaluation programme."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    programme_id: str
    grouping_policy_version: str
    source_training_package_id: str
    source_training_package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    examples: tuple[PartitionedTrainingExample, ...] = Field(min_length=1)
    external_validation_available: bool
    dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    partition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def family_isolation(self) -> Self:
        partitions: dict[str, set[PartitionName]] = {}
        for item in self.examples:
            partitions.setdefault(item.identity.application_family_id, set()).add(item.partition)
        if any(len(values) != 1 for values in partitions.values()):
            raise ValueError("an application family cannot cross partition boundaries")
        names = {item.partition for item in self.examples}
        available = {
            "development_training",
            "development_calibration",
            "external_holdout",
        }.issubset(names)
        if self.external_validation_available != available:
            raise ValueError("external validation availability must reflect all three partitions")
        return self


def partitioned_dataset_sha256(
    value: PartitionedProductionDataset | dict[str, object],
) -> str:
    return canonical_sha256(value, exclude={"partition_sha256"})


def _surrogate(namespace: str, key: str) -> int:
    digest = hashlib.sha256(f"{namespace}\0{key}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % _MAX_SURROGATE_ID + 1


def _training_projection(
    items: tuple[PartitionedTrainingExample, ...],
) -> tuple[TrainingExample, ...]:
    projected: list[TrainingExample] = []
    scan_ids: dict[int, str] = {}
    observation_ids: dict[int, str] = {}
    for item in items:
        scan_id = _surrogate("scan", item.identity.scan_key)
        observation_id = _surrogate("observation", item.identity.observation_key)
        if scan_id in scan_ids and scan_ids[scan_id] != item.identity.scan_key:
            raise GroupingBoundaryError("hierarchical scan surrogate collision detected")
        if (
            observation_id in observation_ids
            and observation_ids[observation_id] != item.identity.observation_key
        ):
            raise GroupingBoundaryError("hierarchical observation surrogate collision detected")
        scan_ids[scan_id] = item.identity.scan_key
        observation_ids[observation_id] = item.identity.observation_key
        projected.append(
            item.example.model_copy(
                update={"scan_id": scan_id, "observation_id": observation_id}
            )
        )
    return tuple(sorted(projected, key=lambda current: (current.scan_id, current.observation_id)))


def build_partitioned_production_dataset(
    package: ProductionTrainingPackage,
    registry: PartitionRegistry,
    *,
    programme_id: str,
) -> PartitionedProductionDataset:
    """Bind every example to its stable family assignment for one programme."""

    if production_training_package_sha256(package) != package.package_sha256:
        raise GroupingBoundaryError("production training package integrity failed")
    events = registry.events(programme_id)
    if not events:
        raise GroupingBoundaryError("partition programme has no assignments")
    assignments = {event.application_family_id: event.partition for event in events}
    policy = events[0].grouping_policy_version
    applications = {item.application_id: item for item in package.applications}
    identities = {
        application_id: application_identity(application)
        for application_id, application in applications.items()
    }

    result: list[PartitionedTrainingExample] = []
    for item in package.examples:
        application = applications.get(item.application_id)
        identity = identities.get(item.application_id)
        if application is None or identity is None:
            raise GroupingBoundaryError("training example references an unknown application")
        partition = assignments.get(identity.application_family_id)
        if partition is None:
            raise GroupingBoundaryError(
                "every released application family must have a frozen partition assignment"
            )
        scan_key = (
            f"{identity.application_instance_id}:"
            f"{identity.deployment_environment_id}:scan:{item.example.scan_id}"
        )
        observation_key = f"{scan_key}:observation:{item.source_reference_sha256}"
        result.append(
            PartitionedTrainingExample(
                source_reference_sha256=item.source_reference_sha256,
                partition=partition,
                identity=HierarchicalExampleIdentity(
                    application_family_id=identity.application_family_id,
                    application_instance_id=identity.application_instance_id,
                    deployment_environment_id=identity.deployment_environment_id,
                    authorization_id=application.authorization_id,
                    campaign_id=package.campaign_id,
                    scan_key=scan_key,
                    observation_key=observation_key,
                    legacy_scan_id=item.example.scan_id,
                    legacy_observation_id=item.example.observation_id,
                ),
                example=item.example,
            )
        )
    result.sort(key=lambda current: current.source_reference_sha256)
    names = {item.partition for item in result}
    external_available = {
        "development_training",
        "development_calibration",
        "external_holdout",
    }.issubset(names)
    source_examples = tuple(item.example for item in result)
    base: dict[str, object] = {
        "schema_version": 1,
        "programme_id": programme_id,
        "grouping_policy_version": policy,
        "source_training_package_id": package.package_id,
        "source_training_package_sha256": package.package_sha256,
        "examples": [item.model_dump(mode="json") for item in result],
        "external_validation_available": external_available,
        "dataset_sha256": dataset_sha256(source_examples),
        "partition_sha256": _ZERO_HASH,
    }
    base["partition_sha256"] = partitioned_dataset_sha256(base)
    return PartitionedProductionDataset.model_validate(base)


def examples_for_partition(
    dataset: PartitionedProductionDataset,
    partition: PartitionName,
) -> tuple[TrainingExample, ...]:
    """Return collision-safe compatibility examples for exactly one partition."""

    selected = tuple(item for item in dataset.examples if item.partition == partition)
    if not selected:
        return ()
    return _training_projection(selected)


class PartitionedGovernedModelCandidate(BaseModel):
    """Production candidate proving it consumed only development-training families."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    training_mode: Literal["partitioned_production_candidate"] = "partitioned_production_candidate"
    programme_id: str
    partition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_training_package_id: str
    source_training_package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_release_id: str
    source_release_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    development_dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    external_validation_available: bool
    model: ModelArtifact
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def partitioned_candidate_sha256(
    value: PartitionedGovernedModelCandidate | dict[str, object],
) -> str:
    return canonical_sha256(value, exclude={"candidate_sha256"})


def _validate_sources(
    dataset: PartitionedProductionDataset,
    package: ProductionTrainingPackage,
    ledger: TrainingReleaseLedger,
    release_package: CampaignReleasePackage,
) -> tuple[TrainingExample, ...]:
    if partitioned_dataset_sha256(dataset) != dataset.partition_sha256:
        raise GroupingBoundaryError("partitioned dataset integrity failed")
    if production_training_package_sha256(package) != package.package_sha256:
        raise GroupingBoundaryError("production training package integrity failed")
    if dataset.source_training_package_sha256 != package.package_sha256:
        raise GroupingBoundaryError("partitioned dataset is bound to a different training package")
    if package.source_release_id != release_package.release_id:
        raise GroupingBoundaryError("training package release identity does not match")
    if package.source_release_package_sha256 != release_package.package_sha256:
        raise GroupingBoundaryError("training package release digest does not match")
    try:
        ledger.require_active(release_package)
    except ReleaseTrainingBoundaryError as exc:
        raise GroupingBoundaryError(str(exc)) from exc
    examples = examples_for_partition(dataset, "development_training")
    if not examples:
        raise GroupingBoundaryError("development-training partition is empty")
    return examples


def _candidate(
    dataset: PartitionedProductionDataset,
    package: ProductionTrainingPackage,
    artifact: ModelArtifact,
) -> PartitionedGovernedModelCandidate:
    development = examples_for_partition(dataset, "development_training")
    development_digest = dataset_sha256(development)
    if artifact.dataset_sha256 != development_digest:
        raise GroupingBoundaryError("trained artifact is not bound to the development partition")
    values: dict[str, object] = {
        "schema_version": 1,
        "training_mode": "partitioned_production_candidate",
        "programme_id": dataset.programme_id,
        "partition_sha256": dataset.partition_sha256,
        "source_training_package_id": package.package_id,
        "source_training_package_sha256": package.package_sha256,
        "source_release_id": package.source_release_id,
        "source_release_manifest_sha256": package.source_release_manifest_sha256,
        "development_dataset_sha256": development_digest,
        "external_validation_available": dataset.external_validation_available,
        "model": artifact,
        "candidate_sha256": _ZERO_HASH,
    }
    values["candidate_sha256"] = partitioned_candidate_sha256(values)
    return PartitionedGovernedModelCandidate.model_validate(values)


def train_partitioned_production_baseline(
    dataset: PartitionedProductionDataset,
    package: ProductionTrainingPackage,
    ledger: TrainingReleaseLedger,
    release_package: CampaignReleasePackage,
    **training_options,
) -> PartitionedGovernedModelCandidate:
    """Fit only development-training families while reserving other partitions."""

    examples = _validate_sources(dataset, package, ledger, release_package)
    artifact = train_baseline(examples, **training_options)
    return _candidate(dataset, package, artifact)


def train_partitioned_production_tuned(
    dataset: PartitionedProductionDataset,
    package: ProductionTrainingPackage,
    ledger: TrainingReleaseLedger,
    release_package: CampaignReleasePackage,
    **training_options,
) -> PartitionedGovernedModelCandidate:
    """Tune only within development-training families; calibration/holdout stay untouched."""

    examples = _validate_sources(dataset, package, ledger, release_package)
    artifact = train_tuned(examples, **training_options)
    return _candidate(dataset, package, artifact)


__all__ = [
    "GroupingBoundaryError",
    "HierarchicalApplicationIdentity",
    "HierarchicalExampleIdentity",
    "PartitionAssignmentEvent",
    "PartitionRegistry",
    "PartitionedGovernedModelCandidate",
    "PartitionedProductionDataset",
    "PartitionedTrainingExample",
    "application_identity",
    "build_partitioned_production_dataset",
    "examples_for_partition",
    "partition_event_sha256",
    "partitioned_candidate_sha256",
    "partitioned_dataset_sha256",
    "train_partitioned_production_baseline",
    "train_partitioned_production_tuned",
]
