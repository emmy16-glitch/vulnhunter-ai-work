"""Integration tests for benchmark generation, review, and training provenance."""

import asyncio
import json
from pathlib import Path

import pytest

from vulnhunter.benchmark import (
    apply_scenario_review,
    benchmark_status,
    load_manifest,
    manifest_sha256,
    pending_by_scenario,
    run_benchmark_suite,
)
from vulnhunter.exceptions import BenchmarkError, BenchmarkManifestError
from vulnhunter.ml import BenchmarkProvenance, build_dataset, train_baseline
from vulnhunter.observations.storage import ScanRepository


def _repository(database: Path) -> ScanRepository:
    repository = ScanRepository.from_path(database)
    repository.initialize()
    return repository


def test_benchmark_run_creates_isolated_scans_and_manifest(tmp_path: Path) -> None:
    database = tmp_path / "benchmark.db"
    manifest_path = tmp_path / "manifest.json"

    manifest = asyncio.run(run_benchmark_suite(database, manifest_path))
    loaded = load_manifest(manifest_path)
    repository = _repository(database)

    assert loaded == manifest
    assert len(manifest.scenarios) == 6
    assert len(manifest.expectations) >= 20
    assert len({item.scan_id for item in manifest.scenarios}) == 6
    assert {item.suggested_label for item in manifest.expectations} == {
        "confirmed",
        "false_positive",
    }
    assert benchmark_status(manifest, database, repository).pending == len(manifest.expectations)


def test_benchmark_refuses_nonempty_database(tmp_path: Path) -> None:
    database = tmp_path / "benchmark.db"
    repository = _repository(database)
    repository.create_scan("http://127.0.0.1:8000/")

    with pytest.raises(BenchmarkError, match="must be empty"):
        asyncio.run(
            run_benchmark_suite(
                database,
                tmp_path / "manifest.json",
            )
        )


def test_manifest_tampering_is_detected(tmp_path: Path) -> None:
    database = tmp_path / "benchmark.db"
    manifest_path = tmp_path / "manifest.json"
    asyncio.run(run_benchmark_suite(database, manifest_path))

    envelope = json.loads(manifest_path.read_text(encoding="utf-8"))
    envelope["manifest"]["run_id"] = "00000000-0000-0000-0000-000000000000"
    manifest_path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(BenchmarkManifestError, match="integrity"):
        load_manifest(manifest_path)


def test_scenario_review_requires_explicit_decision(tmp_path: Path) -> None:
    database = tmp_path / "benchmark.db"
    manifest_path = tmp_path / "manifest.json"
    manifest = asyncio.run(run_benchmark_suite(database, manifest_path))
    repository = _repository(database)
    scenario_id = manifest.scenarios[0].scenario_id
    expected_count = len(pending_by_scenario(manifest, database, repository)[scenario_id])

    labelled = apply_scenario_review(
        manifest,
        database,
        repository,
        scenario_id,
        "accept",
    )

    assert len(labelled) == expected_count
    assert {item.review_label for item in labelled} == {"confirmed"}
    assert benchmark_status(manifest, database, repository).pending == (
        len(manifest.expectations) - expected_count
    )


def test_reviewed_benchmark_trains_provenance_marked_model(tmp_path: Path) -> None:
    database = tmp_path / "benchmark.db"
    manifest_path = tmp_path / "manifest.json"
    manifest = asyncio.run(run_benchmark_suite(database, manifest_path))
    repository = _repository(database)

    for scenario_id in pending_by_scenario(manifest, database, repository):
        apply_scenario_review(
            manifest,
            database,
            repository,
            scenario_id,
            "accept",
        )

    status = benchmark_status(manifest, database, repository)
    dataset = build_dataset(repository.list_training_observations())
    artifact = train_baseline(
        dataset,
        benchmark_provenance=BenchmarkProvenance(
            run_id=manifest.run_id,
            catalog_version=manifest.catalog_version,
            manifest_sha256=manifest_sha256(manifest),
        ),
    )

    assert status.complete is True
    assert artifact.artifact_version == 3
    assert artifact.training_context == "controlled_benchmark"
    assert artifact.benchmark_run_id == manifest.run_id
    assert artifact.benchmark_catalog_version == manifest.catalog_version
    assert artifact.benchmark_manifest_sha256 == manifest_sha256(manifest)
    assert set(artifact.training_scan_ids).isdisjoint(artifact.holdout_scan_ids)
