from datetime import UTC, datetime

import pytest

from vulnhunter.ml.dataset import dataset_sha256
from vulnhunter.ml.grouping import (
    GroupingBoundaryError,
    PartitionRegistry,
    application_identity,
    build_partitioned_production_dataset,
    examples_for_partition,
    partition_event_sha256,
    partitioned_dataset_sha256,
)
from vulnhunter.ml.models import TrainingExample
from vulnhunter.ml.release_training import (
    ProductionTrainingPackage,
    TrainingPackageApplication,
    TrainingPackageExample,
    production_training_package_sha256,
)

NOW = datetime(2026, 8, 8, 14, 0, tzinfo=UTC)
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
ZERO = "0" * 64


def _example(observation_id: int, scan_id: int, label: str, seed: str) -> TrainingExample:
    return TrainingExample(
        observation_id=observation_id,
        scan_id=scan_id,
        category="debug_error_exposure" if label == "confirmed" else "missing_header",
        severity="high" if label == "confirmed" else "low",
        title=f"Observation {observation_id}",
        description="Redacted governed evidence.",
        url=f"http://127.0.0.1/{observation_id}",
        evidence={"status_code": 500 if label == "confirmed" else 200},
        fingerprint=(seed * 64)[:64],
        label=label,
    )


def _package(*, families=("python-django", "node-express", "go-chi"), overlap=True):
    applications = []
    examples = []
    raw_examples = []
    for app_index, family in enumerate(families):
        application_id = f"application-{app_index + 1:02d}"
        applications.append(
            TrainingPackageApplication(
                application_id=application_id,
                application_record_sha256=HEX_A,
                application_family=family,
                environment=f"owned-local-{app_index + 1}",
                authorization_id=f"authorization-{app_index + 1:02d}",
                authorization_record_sha256=HEX_B,
            )
        )
        for offset in range(4):
            legacy_id = offset + 1 if overlap else app_index * 4 + offset + 1
            label = "confirmed" if offset % 2 == 0 else "false_positive"
            example = _example(
                legacy_id,
                legacy_id,
                label,
                seed=hex(app_index * 4 + offset + 1)[-1],
            )
            raw_examples.append(example)
            examples.append(
                TrainingPackageExample(
                    example=example,
                    example_sha256=(f"{app_index + 1:x}" * 64)[:64],
                    source_reference_sha256=(f"{app_index * 4 + offset + 1:x}" * 64)[:64],
                    application_id=application_id,
                    application_family=family,
                    environment=f"owned-local-{app_index + 1}",
                    review_resolution="consensus",
                    assignment_record_sha256=HEX_C,
                    review_attestation_sha256s=(HEX_C, HEX_D),
                )
            )
    values = {
        "schema_version": 1,
        "package_id": "training-package-hierarchy",
        "source_release_id": "release-hierarchy-01",
        "source_release_manifest_sha256": HEX_A,
        "source_release_package_sha256": HEX_B,
        "campaign_id": "campaign-hierarchy-01",
        "applications": tuple(applications),
        "examples": tuple(examples),
        "excluded_records": (),
        "dataset_sha256": dataset_sha256(tuple(raw_examples)),
        "label_ontology_version": "binary-review-v1",
        "redaction_policy_version": "redaction-v1",
        "privacy_classification": "owner_private_redacted",
        "permitted_tasks": ("review_priority",),
        "retention_policy": "Owner-private research retention.",
        "generator_version": "0.1.0",
        "source_commit": "a" * 40,
        "package_sha256": ZERO,
    }
    values["package_sha256"] = production_training_package_sha256(values)
    return ProductionTrainingPackage.model_validate(values)


def _assign(registry, package, partitions, *, programme="evaluation-2026-01"):
    for application, partition in zip(package.applications, partitions, strict=True):
        identity = application_identity(application)
        registry.assign_family(
            programme_id=programme,
            grouping_policy_version="family-instance-environment-v1",
            application_family_id=identity.application_family_id,
            partition=partition,
            actor_id="ml-governance-admin",
            reason="Freeze family assignment before candidate development.",
            now=NOW,
        )


def test_application_identity_is_stable_and_not_derived_from_scan_ids():
    package = _package()
    first = application_identity(package.applications[0])
    again = application_identity(package.applications[0])

    assert first == again
    assert first.application_family_id.startswith("family-")
    assert first.application_instance_id.startswith("instance-")
    assert first.deployment_environment_id.startswith("environment-")
    assert "scan" not in first.application_family_id


def test_partition_registry_is_append_only_idempotent_and_hash_chained(tmp_path):
    registry = PartitionRegistry(tmp_path / "partitions")
    package = _package()
    family = application_identity(package.applications[0]).application_family_id

    first = registry.assign_family(
        programme_id="evaluation-2026-01",
        grouping_policy_version="family-v1",
        application_family_id=family,
        partition="development_training",
        actor_id="ml-admin",
        reason="Initial family assignment.",
        now=NOW,
    )
    repeated = registry.assign_family(
        programme_id="evaluation-2026-01",
        grouping_policy_version="family-v1",
        application_family_id=family,
        partition="development_training",
        actor_id="ml-admin",
        reason="Idempotent retry.",
        now=NOW,
    )

    assert repeated == first
    assert partition_event_sha256(first) == first.event_sha256
    assert registry.events("evaluation-2026-01") == (first,)
    assert (tmp_path / "partitions").stat().st_mode & 0o777 == 0o700


def test_family_cannot_cross_partition_inside_one_programme(tmp_path):
    registry = PartitionRegistry(tmp_path / "partitions")
    package = _package()
    family = application_identity(package.applications[0]).application_family_id
    registry.assign_family(
        programme_id="evaluation-2026-01",
        grouping_policy_version="family-v1",
        application_family_id=family,
        partition="development_training",
        actor_id="ml-admin",
        reason="Initial assignment.",
        now=NOW,
    )

    with pytest.raises(GroupingBoundaryError, match="partition is frozen"):
        registry.assign_family(
            programme_id="evaluation-2026-01",
            grouping_policy_version="family-v1",
            application_family_id=family,
            partition="external_holdout",
            actor_id="ml-admin",
            reason="Unsafe reassignment.",
            now=NOW,
        )


def test_partition_reset_requires_existing_superseded_programme(tmp_path):
    registry = PartitionRegistry(tmp_path / "partitions")
    family = application_identity(_package().applications[0]).application_family_id

    with pytest.raises(GroupingBoundaryError, match="does not exist"):
        registry.assign_family(
            programme_id="evaluation-reset-02",
            grouping_policy_version="family-v2",
            application_family_id=family,
            partition="development_training",
            actor_id="ml-admin",
            reason="Start a reset.",
            supersedes_programme_id="missing-programme",
            now=NOW,
        )


def test_every_release_family_requires_a_frozen_assignment(tmp_path):
    registry = PartitionRegistry(tmp_path / "partitions")
    package = _package()
    _assign(
        registry,
        package,
        ("development_training", "development_calibration", "external_holdout"),
    )
    fourth_family = _package(families=("python-django", "node-express", "go-chi", "ruby-rails"))

    with pytest.raises(GroupingBoundaryError, match="every released application family"):
        build_partitioned_production_dataset(
            fourth_family,
            registry,
            programme_id="evaluation-2026-01",
        )


def test_overlapping_legacy_ids_are_isolated_by_hierarchical_keys(tmp_path):
    registry = PartitionRegistry(tmp_path / "partitions")
    package = _package(overlap=True)
    _assign(
        registry,
        package,
        ("development_training", "development_training", "development_training"),
    )
    partitioned = build_partitioned_production_dataset(
        package,
        registry,
        programme_id="evaluation-2026-01",
    )
    projected = examples_for_partition(partitioned, "development_training")

    assert len(projected) == 12
    assert len({example.scan_id for example in projected}) == 12
    assert len({example.observation_id for example in projected}) == 12
    assert partitioned.external_validation_available is False
    assert partitioned_dataset_sha256(partitioned) == partitioned.partition_sha256


def test_external_validation_is_truthful_only_when_all_three_partitions_exist(tmp_path):
    package = _package()
    registry = PartitionRegistry(tmp_path / "partitions")
    _assign(
        registry,
        package,
        ("development_training", "development_calibration", "external_holdout"),
    )
    partitioned = build_partitioned_production_dataset(
        package,
        registry,
        programme_id="evaluation-2026-01",
    )

    assert partitioned.external_validation_available is True
    assert len(examples_for_partition(partitioned, "development_training")) == 4
    assert len(examples_for_partition(partitioned, "development_calibration")) == 4
    assert len(examples_for_partition(partitioned, "external_holdout")) == 4


def test_repeated_release_family_names_reuse_the_same_registry_assignment(tmp_path):
    registry = PartitionRegistry(tmp_path / "partitions")
    first = _package()
    _assign(
        registry,
        first,
        ("development_training", "development_calibration", "external_holdout"),
    )
    repeated_release = _package(overlap=False)

    partitioned = build_partitioned_production_dataset(
        repeated_release,
        registry,
        programme_id="evaluation-2026-01",
    )

    family_partitions = {}
    for item in partitioned.examples:
        family_partitions.setdefault(item.identity.application_family_id, set()).add(item.partition)
    assert all(len(partitions) == 1 for partitions in family_partitions.values())
    assert partitioned.external_validation_available is True
