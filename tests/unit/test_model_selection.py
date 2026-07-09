"""Tests for richer features and training-only grouped model selection."""

from __future__ import annotations

from pathlib import Path

from vulnhunter.ml import (
    BenchmarkProvenance,
    build_feature_schema,
    build_two_fold_group_cv,
    load_model,
    predict,
    save_model,
    train_tuned,
    tune_model,
    vectorize,
)
from vulnhunter.ml.models import TrainingExample


def make_examples() -> tuple[TrainingExample, ...]:
    examples: list[TrainingExample] = []
    observation_id = 1

    for scan_id in range(1, 7):
        confirmed = scan_id <= 3
        label = "confirmed" if confirmed else "false_positive"
        path_prefix = "admin" if confirmed else "docs"

        for suffix, category in enumerate(
            (
                "missing_security_headers",
                "clickjacking_protection_missing",
                "technology_disclosure",
                "directory_listing" if confirmed else "missing_security_headers",
            )
        ):
            evidence: dict[str, object]
            if category == "missing_security_headers":
                evidence = {
                    "missing_headers": [
                        "Content-Security-Policy",
                        "X-Content-Type-Options",
                        "Referrer-Policy",
                    ]
                }
            elif category == "clickjacking_protection_missing":
                evidence = {
                    "x_frame_options_present": False,
                    "csp_frame_ancestors_present": False,
                }
            elif category == "technology_disclosure":
                evidence = {"headers": {"server": "[REDACTED]"}}
            else:
                evidence = {"page_title": "index of /private/", "heading": "index of /private/"}

            examples.append(
                TrainingExample(
                    observation_id=observation_id,
                    scan_id=scan_id,
                    category=category,
                    severity="medium" if category != "technology_disclosure" else "info",
                    title="Passive security signal requires contextual review",
                    description="The signal is reviewed using local application context.",
                    url=(
                        f"http://127.0.0.1:8000/{path_prefix}/"
                        f"{'private' if confirmed else 'guide'}/{suffix}.html"
                    ),
                    evidence=evidence,
                    fingerprint=f"{observation_id:064x}",
                    label=label,
                )
            )
            observation_id += 1

    return tuple(examples)


def test_feature_schema_version_two_adds_privacy_safe_context() -> None:
    examples = make_examples()
    schema = build_feature_schema(examples)
    confirmed_vector = vectorize(examples[0], schema)
    public_vector = vectorize(examples[12], schema)
    names = schema.feature_names

    assert schema.schema_version == 2
    assert confirmed_vector[names.index("url:path_has_admin")] == 1.0
    assert confirmed_vector[names.index("url:path_has_private")] == 1.0
    assert public_vector[names.index("url:path_has_docs")] == 1.0
    assert public_vector[names.index("url:path_has_guide")] == 1.0


def test_two_fold_group_cv_is_disjoint_and_covers_each_example_once() -> None:
    examples = make_examples()
    folds = build_two_fold_group_cv(examples)

    validation_ids = []
    for fold in folds:
        assert {item.scan_id for item in fold.train_examples}.isdisjoint(
            {item.scan_id for item in fold.validation_examples}
        )
        assert {item.label for item in fold.train_examples} == {
            "confirmed",
            "false_positive",
        }
        assert {item.label for item in fold.validation_examples} == {
            "confirmed",
            "false_positive",
        }
        validation_ids.extend(item.observation_id for item in fold.validation_examples)

    assert sorted(validation_ids) == [item.observation_id for item in examples]


def test_model_selection_is_deterministic() -> None:
    examples = make_examples()
    train_examples = tuple(item for item in examples if item.scan_id in {1, 2, 4, 5})

    first = tune_model(train_examples)
    second = tune_model(train_examples)

    assert first == second
    assert first.summary.fold_count == 2
    assert first.summary.candidate_count == 40
    assert first.summary.cross_validation.f1_score == 1.0


def test_tuned_training_uses_version_four_and_locked_holdout() -> None:
    examples = make_examples()
    artifact = train_tuned(
        examples,
        benchmark_provenance=BenchmarkProvenance(
            run_id="00000000-0000-0000-0000-000000000001",
            catalog_version=1,
            manifest_sha256="a" * 64,
        ),
    )

    assert artifact.artifact_version == 4
    assert artifact.tuning is not None
    assert artifact.feature_schema.schema_version == 2
    assert set(artifact.training_scan_ids).isdisjoint(artifact.holdout_scan_ids)
    assert artifact.tuning.cross_validation.test_samples == artifact.training_samples
    assert artifact.evaluation.f1_score == 1.0


def test_tuned_model_round_trip_preserves_prediction(tmp_path: Path) -> None:
    examples = make_examples()
    artifact = train_tuned(examples)
    path = tmp_path / "tuned.json"

    save_model(artifact, path)
    loaded = load_model(path)
    result = predict(examples[0], loaded)

    assert loaded == artifact
    assert result.label == "confirmed"
    assert result.probabilities["confirmed"] >= loaded.decision_threshold
