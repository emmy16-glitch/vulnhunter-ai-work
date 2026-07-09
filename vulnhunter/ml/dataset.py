"""Reviewed-observation dataset construction, hashing, and export."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path

from vulnhunter.ml.models import ObservationInput, TrainingExample
from vulnhunter.observations.models import ObservationSummary

_TRAINING_LABELS = frozenset({"confirmed", "false_positive"})


def to_model_input(observation: ObservationSummary) -> ObservationInput:
    """Convert any persisted observation into safe model input fields."""
    return ObservationInput(
        observation_id=observation.id,
        scan_id=observation.scan_id,
        category=observation.category,
        severity=observation.severity,
        title=observation.title,
        description=observation.description,
        url=observation.url,
        evidence=observation.evidence,
    )


def to_training_example(observation: ObservationSummary) -> TrainingExample:
    """Convert one eligible human-reviewed observation into a safe example."""
    if observation.review_label not in _TRAINING_LABELS:
        raise ValueError(
            "Only confirmed and false_positive observations are eligible for training."
        )

    return TrainingExample(
        **to_model_input(observation).model_dump(),
        label=observation.review_label,
    )


def build_dataset(
    observations: Iterable[ObservationSummary],
) -> tuple[TrainingExample, ...]:
    """Build an ID-sorted dataset from eligible reviewed observations."""
    examples = [
        to_training_example(observation)
        for observation in observations
        if observation.review_label in _TRAINING_LABELS
    ]
    return tuple(sorted(examples, key=lambda item: item.observation_id))


def dataset_sha256(examples: Iterable[TrainingExample]) -> str:
    """Hash canonical dataset content for reproducibility and provenance."""
    digest = hashlib.sha256()

    for example in examples:
        line = json.dumps(
            example.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest.update(line)
        digest.update(b"\n")

    return digest.hexdigest()


def export_jsonl(examples: Iterable[TrainingExample], output_path: Path) -> int:
    """Atomically export reviewed examples as deterministic JSON Lines."""
    resolved_path = output_path.expanduser().resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = resolved_path.with_suffix(resolved_path.suffix + ".tmp")
    count = 0

    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as handle:
            for example in examples:
                handle.write(
                    json.dumps(
                        example.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                handle.write("\n")
                count += 1

            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, resolved_path)
        return count
    finally:
        temporary_path.unlink(missing_ok=True)
