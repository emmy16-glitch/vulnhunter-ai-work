"""Dataset deduplication, conflict detection, and training-readiness gates."""

from __future__ import annotations

from collections import Counter, defaultdict

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.exceptions import InsufficientTrainingDataError
from vulnhunter.ml.models import TrainingExample, TrainingLabel
from vulnhunter.ml.splitting import split_by_scan_groups


class DatasetQualityReport(BaseModel):
    """Explain whether reviewed data can support a defensible baseline model."""

    model_config = ConfigDict(frozen=True)

    source_samples: int = Field(ge=0)
    unique_samples: int = Field(ge=0)
    duplicate_samples: int = Field(ge=0)
    distinct_scans: int = Field(ge=0)
    class_counts: dict[TrainingLabel, int]
    scans_per_class: dict[TrainingLabel, int]
    conflicting_fingerprints: tuple[str, ...] = ()
    ready: bool
    blocking_reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class PreparedTrainingDataset(BaseModel):
    """Canonical reviewed examples plus their quality assessment."""

    model_config = ConfigDict(frozen=True)

    examples: tuple[TrainingExample, ...]
    report: DatasetQualityReport


def _deduplicate(
    examples: tuple[TrainingExample, ...],
) -> tuple[tuple[TrainingExample, ...], tuple[str, ...]]:
    grouped: dict[str, list[TrainingExample]] = defaultdict(list)
    for example in examples:
        grouped[example.fingerprint].append(example)

    canonical: list[TrainingExample] = []
    conflicts: list[str] = []

    for fingerprint, group in grouped.items():
        labels = {example.label for example in group}
        if len(labels) > 1:
            conflicts.append(fingerprint)
            continue

        canonical.append(min(group, key=lambda item: item.observation_id))

    return (
        tuple(sorted(canonical, key=lambda item: item.observation_id)),
        tuple(sorted(conflicts)),
    )


def assess_dataset_quality(
    examples: tuple[TrainingExample, ...],
    *,
    minimum_samples: int = 20,
    minimum_per_class: int = 5,
    minimum_scans: int = 4,
    minimum_scans_per_class: int = 2,
    test_fraction: float = 0.2,
    random_seed: int = 42,
) -> PreparedTrainingDataset:
    """Deduplicate reviewed data and evaluate all training-quality gates."""
    if minimum_samples < 4:
        raise ValueError("minimum_samples must be at least 4.")
    if minimum_per_class < 2:
        raise ValueError("minimum_per_class must be at least 2.")
    if minimum_scans < 2:
        raise ValueError("minimum_scans must be at least 2.")
    if minimum_scans_per_class < 2:
        raise ValueError("minimum_scans_per_class must be at least 2.")

    canonical, conflicts = _deduplicate(examples)
    class_counts: Counter[TrainingLabel] = Counter(example.label for example in canonical)
    scans_by_class: dict[TrainingLabel, set[int]] = {
        "confirmed": set(),
        "false_positive": set(),
    }
    for example in canonical:
        scans_by_class[example.label].add(example.scan_id)

    distinct_scans = len({example.scan_id for example in canonical})
    blocking: list[str] = []
    warnings: list[str] = []

    if conflicts:
        blocking.append(f"{len(conflicts)} fingerprint(s) have conflicting human labels.")

    if len(canonical) < minimum_samples:
        blocking.append(
            f"At least {minimum_samples} unique reviewed samples are required; "
            f"found {len(canonical)}."
        )

    for label in ("confirmed", "false_positive"):
        if class_counts[label] < minimum_per_class:
            blocking.append(
                f"At least {minimum_per_class} unique {label!r} samples are "
                f"required; found {class_counts[label]}."
            )

        scan_count = len(scans_by_class[label])
        if scan_count < minimum_scans_per_class:
            blocking.append(
                f"Label {label!r} must occur in at least "
                f"{minimum_scans_per_class} independent scans; found {scan_count}."
            )

    if distinct_scans < minimum_scans:
        blocking.append(
            f"At least {minimum_scans} distinct scans are required; found {distinct_scans}."
        )

    duplicate_samples = (
        len(examples)
        - len(canonical)
        - len([example for example in examples if example.fingerprint in set(conflicts)])
    )
    if duplicate_samples > 0:
        warnings.append(
            f"{duplicate_samples} repeated observation(s) will be excluded from training."
        )

    if not blocking:
        try:
            split_by_scan_groups(
                canonical,
                test_fraction=test_fraction,
                random_seed=random_seed,
            )
        except (InsufficientTrainingDataError, ValueError) as exc:
            blocking.append(str(exc))

    report = DatasetQualityReport(
        source_samples=len(examples),
        unique_samples=len(canonical),
        duplicate_samples=max(0, duplicate_samples),
        distinct_scans=distinct_scans,
        class_counts={
            "confirmed": class_counts["confirmed"],
            "false_positive": class_counts["false_positive"],
        },
        scans_per_class={
            "confirmed": len(scans_by_class["confirmed"]),
            "false_positive": len(scans_by_class["false_positive"]),
        },
        conflicting_fingerprints=conflicts,
        ready=not blocking,
        blocking_reasons=tuple(blocking),
        warnings=tuple(warnings),
    )
    return PreparedTrainingDataset(examples=canonical, report=report)
