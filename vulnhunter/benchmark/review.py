"""Human-review operations for controlled benchmark expectations."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from vulnhunter.benchmark.models import (
    BenchmarkExpectation,
    BenchmarkManifest,
    BenchmarkStatus,
)
from vulnhunter.exceptions import BenchmarkManifestError
from vulnhunter.ml.models import TrainingLabel
from vulnhunter.observations.models import ObservationSummary
from vulnhunter.observations.storage import ScanRepository

ReviewDecision = Literal["accept", "confirmed", "false_positive"]


def validate_manifest_database(
    manifest: BenchmarkManifest,
    database_path: Path,
    repository: ScanRepository,
) -> dict[int, ObservationSummary]:
    """Verify database identity and every observation fingerprint in a manifest."""
    resolved_database = str(database_path.expanduser().resolve())
    if manifest.database_path != resolved_database:
        raise BenchmarkManifestError(
            "Benchmark manifest belongs to a different SQLite database path."
        )

    observations: dict[int, ObservationSummary] = {}
    for expectation in manifest.expectations:
        try:
            observation = repository.get_observation(expectation.observation_id)
        except ValueError as exc:
            raise BenchmarkManifestError(
                f"Benchmark observation {expectation.observation_id} is missing."
            ) from exc

        if observation.scan_id != expectation.scan_id:
            raise BenchmarkManifestError("Benchmark observation scan identity changed.")
        if observation.fingerprint != expectation.fingerprint:
            raise BenchmarkManifestError("Benchmark observation fingerprint changed.")
        observations[observation.id] = observation

    return observations


def benchmark_status(
    manifest: BenchmarkManifest,
    database_path: Path,
    repository: ScanRepository,
) -> BenchmarkStatus:
    """Summarise review progress after validating manifest/database consistency."""
    observations = validate_manifest_database(manifest, database_path, repository)
    counts = Counter(item.review_label for item in observations.values())
    mismatched = sum(
        1
        for expectation in manifest.expectations
        if observations[expectation.observation_id].review_label in {"confirmed", "false_positive"}
        and observations[expectation.observation_id].review_label != expectation.suggested_label
    )
    pending = counts["unreviewed"] + counts["needs_review"]

    return BenchmarkStatus(
        total_expectations=len(manifest.expectations),
        pending=pending,
        confirmed=counts["confirmed"],
        false_positive=counts["false_positive"],
        needs_review=counts["needs_review"],
        mismatched=mismatched,
        complete=pending == 0,
    )


def pending_by_scenario(
    manifest: BenchmarkManifest,
    database_path: Path,
    repository: ScanRepository,
) -> dict[str, tuple[BenchmarkExpectation, ...]]:
    """Group unreviewed expectations by scenario in manifest order."""
    observations = validate_manifest_database(manifest, database_path, repository)
    grouped: dict[str, list[BenchmarkExpectation]] = defaultdict(list)

    for expectation in manifest.expectations:
        observation = observations[expectation.observation_id]
        if observation.review_label in {"unreviewed", "needs_review"}:
            grouped[expectation.scenario_id].append(expectation)

    return {
        scenario.scenario_id: tuple(grouped.get(scenario.scenario_id, ()))
        for scenario in manifest.scenarios
        if grouped.get(scenario.scenario_id)
    }


def apply_scenario_review(
    manifest: BenchmarkManifest,
    database_path: Path,
    repository: ScanRepository,
    scenario_id: str,
    decision: ReviewDecision,
) -> tuple[ObservationSummary, ...]:
    """Apply one explicit human decision to pending findings in a scenario."""
    pending = pending_by_scenario(manifest, database_path, repository)
    expectations = pending.get(scenario_id)
    if not expectations:
        raise ValueError(f"Scenario {scenario_id!r} has no pending benchmark findings.")

    suggested_labels = {item.suggested_label for item in expectations}
    if len(suggested_labels) != 1:
        raise BenchmarkManifestError("Scenario contains inconsistent suggestions.")

    label: TrainingLabel = next(iter(suggested_labels)) if decision == "accept" else decision
    note = (
        f"Controlled benchmark {manifest.run_id}, scenario {scenario_id}: "
        f"human review decision={decision}; applied label={label}."
    )
    return repository.label_observations(
        tuple(item.observation_id for item in expectations),
        label,
        note=note,
    )
