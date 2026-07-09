"""Tests for VulnHunter's reviewed-data baseline ML pipeline."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnhunter.exceptions import InsufficientTrainingDataError, ModelArtifactError
from vulnhunter.ml import (
    assess_dataset_quality,
    build_dataset,
    build_feature_schema,
    export_jsonl,
    load_model,
    predict,
    save_model,
    split_by_scan_groups,
    train_baseline,
    vectorize,
)
from vulnhunter.ml.dataset import to_model_input
from vulnhunter.ml.models import ModelArtifact, TrainingExample
from vulnhunter.observations.models import ObservationSummary


def make_summary(
    observation_id: int,
    *,
    label: str,
    confirmed: bool,
    scan_id: int | None = None,
    fingerprint: str | None = None,
) -> ObservationSummary:
    if confirmed:
        category = "debug_error_exposure"
        severity = "high"
        title = "Detailed application error information was exposed"
        description = "A stack trace and debug exception page were detected."
        evidence = {
            "status_code": 500,
            "detected_indicators": ["traceback", "stack trace"],
        }
        url = f"http://127.0.0.1:8000/app/error/{observation_id}"
    else:
        category = "technology_disclosure"
        severity = "info"
        title = "Generic server banner requires contextual review"
        description = "A low-risk informational header was observed."
        evidence = {"headers": {"server": "lab-server"}}
        url = f"http://127.0.0.1:8000/app/info/{observation_id}"

    return ObservationSummary(
        id=observation_id,
        scan_id=scan_id or ((observation_id - 1) % 4) + 1,
        page_id=observation_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        url=url,
        evidence=evidence,
        fingerprint=fingerprint or f"{observation_id:064x}",
        review_label=label,
        review_note="review note must never enter model features",
        reviewed_at=datetime.now(UTC),
    )


def make_dataset() -> tuple[TrainingExample, ...]:
    observations = [
        make_summary(index, label="confirmed", confirmed=True) for index in range(1, 13)
    ]
    observations.extend(
        make_summary(index, label="false_positive", confirmed=False) for index in range(13, 25)
    )
    return build_dataset(observations)


def test_build_dataset_excludes_non_binary_review_labels() -> None:
    observations = (
        make_summary(1, label="confirmed", confirmed=True),
        make_summary(2, label="false_positive", confirmed=False),
        make_summary(3, label="needs_review", confirmed=True),
        make_summary(4, label="unreviewed", confirmed=False),
    )

    dataset = build_dataset(observations)

    assert [example.observation_id for example in dataset] == [1, 2]
    assert {example.label for example in dataset} == {"confirmed", "false_positive"}
    assert dataset[0].fingerprint == f"{1:064x}"


def test_feature_engineering_is_deterministic_and_excludes_review_note() -> None:
    summary = make_summary(1, label="confirmed", confirmed=True)
    example = build_dataset((summary,))[0]
    schema = build_feature_schema((example,))

    assert vectorize(example, schema) == vectorize(example, schema)
    assert "review" not in schema.tokens
    assert "note" not in schema.tokens
    assert len(vectorize(example, schema)) == len(schema.feature_names)


def test_export_jsonl_is_deterministic_and_private(tmp_path: Path) -> None:
    output = tmp_path / "training.jsonl"
    dataset = make_dataset()[:2]

    count = export_jsonl(dataset, output)

    assert count == 2
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert rows[0]["observation_id"] == 1
    assert rows[0]["fingerprint"] == f"{1:064x}"
    assert "review_note" not in rows[0]
    assert output.stat().st_mode & 0o777 == 0o600


def test_readiness_detects_duplicate_and_keeps_canonical_example() -> None:
    dataset = make_dataset()
    duplicate = dataset[0].model_copy(update={"observation_id": 25, "scan_id": 5})

    prepared = assess_dataset_quality(dataset + (duplicate,))

    assert prepared.report.ready is True
    assert prepared.report.source_samples == 25
    assert prepared.report.unique_samples == 24
    assert prepared.report.duplicate_samples == 1
    assert prepared.examples[0].observation_id == 1


def test_readiness_blocks_conflicting_human_labels() -> None:
    dataset = make_dataset()
    conflict = dataset[0].model_copy(
        update={"observation_id": 25, "scan_id": 5, "label": "false_positive"}
    )

    prepared = assess_dataset_quality(dataset + (conflict,))

    assert prepared.report.ready is False
    assert prepared.report.conflicting_fingerprints == (dataset[0].fingerprint,)
    assert "conflicting human labels" in " ".join(prepared.report.blocking_reasons)


def test_scan_group_split_is_reproducible_and_has_no_scan_leakage() -> None:
    dataset = make_dataset()

    first = split_by_scan_groups(dataset, test_fraction=0.2, random_seed=7)
    second = split_by_scan_groups(dataset, test_fraction=0.2, random_seed=7)

    assert first == second
    train, holdout = first
    assert {item.scan_id for item in train}.isdisjoint({item.scan_id for item in holdout})
    assert {item.label for item in train} == {"confirmed", "false_positive"}
    assert {item.label for item in holdout} == {"confirmed", "false_positive"}


def test_training_fails_when_reviewed_data_is_insufficient() -> None:
    with pytest.raises(InsufficientTrainingDataError, match="quality gates"):
        train_baseline(make_dataset()[:4])


def test_training_fails_when_all_examples_come_from_one_scan() -> None:
    one_scan = tuple(example.model_copy(update={"scan_id": 1}) for example in make_dataset())

    with pytest.raises(InsufficientTrainingDataError, match="quality gates"):
        train_baseline(one_scan)


def test_training_is_reproducible_except_creation_time() -> None:
    dataset = make_dataset()

    first = train_baseline(dataset, random_seed=7)
    second = train_baseline(dataset, random_seed=7)

    assert first.dataset_sha256 == second.dataset_sha256
    assert first.feature_schema == second.feature_schema
    assert first.class_log_priors == second.class_log_priors
    assert first.feature_log_probabilities == second.feature_log_probabilities
    assert first.evaluation == second.evaluation
    assert first.evaluation.f1_score == 1.0
    assert set(first.training_scan_ids).isdisjoint(first.holdout_scan_ids)
    assert first.split_strategy == "scan_group_stratified"


def test_model_round_trip_and_prediction(tmp_path: Path) -> None:
    dataset = make_dataset()
    artifact = train_baseline(dataset)
    model_path = tmp_path / "baseline.json"

    save_model(artifact, model_path)
    loaded = load_model(model_path)
    prediction = predict(
        to_model_input(make_summary(25, label="unreviewed", confirmed=True)), loaded
    )

    assert loaded == artifact
    assert prediction.label == "confirmed"
    assert prediction.confidence > 0.5
    assert model_path.stat().st_mode & 0o777 == 0o600


def test_version_one_artifact_remains_loadable() -> None:
    artifact = train_baseline(make_dataset())
    payload = artifact.model_dump()
    payload["artifact_version"] = 1
    for field in (
        "source_samples",
        "deduplicated_samples",
        "duplicate_samples_removed",
        "split_strategy",
        "training_scan_ids",
        "holdout_scan_ids",
    ):
        payload.pop(field)

    loaded = ModelArtifact.model_validate(payload)

    assert loaded.artifact_version == 1
    assert loaded.split_strategy == "observation_stratified"


def test_malformed_model_is_rejected(tmp_path: Path) -> None:
    model_path = tmp_path / "bad.json"
    model_path.write_text("not-json", encoding="utf-8")

    with pytest.raises(ModelArtifactError, match="malformed"):
        load_model(model_path)
