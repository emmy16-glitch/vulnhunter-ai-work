"""Deterministic training, evaluation, persistence, tuning, and prediction."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter import __version__
from vulnhunter.exceptions import InsufficientTrainingDataError, ModelArtifactError
from vulnhunter.ml.dataset import dataset_sha256
from vulnhunter.ml.estimators import (
    FittedParameters,
    evaluate_predictions,
    fit_model,
    predict_vector,
)
from vulnhunter.ml.features import build_feature_schema, vectorize, vectorize_many
from vulnhunter.ml.models import (
    BenchmarkProvenance,
    ModelArtifact,
    ObservationInput,
    Prediction,
    TrainingExample,
)
from vulnhunter.ml.quality import PreparedTrainingDataset, assess_dataset_quality
from vulnhunter.ml.splitting import split_by_scan_groups
from vulnhunter.ml.tuning import tune_model

_MAXIMUM_MODEL_BYTES = 10 * 1024 * 1024


def _prepare_dataset(
    examples: tuple[TrainingExample, ...],
    *,
    minimum_samples: int,
    minimum_per_class: int,
    minimum_scans: int,
    minimum_scans_per_class: int,
    test_fraction: float,
    random_seed: int,
) -> PreparedTrainingDataset:
    prepared = assess_dataset_quality(
        examples,
        minimum_samples=minimum_samples,
        minimum_per_class=minimum_per_class,
        minimum_scans=minimum_scans,
        minimum_scans_per_class=minimum_scans_per_class,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )
    if not prepared.report.ready:
        raise InsufficientTrainingDataError(
            "Training data failed quality gates: " + " ".join(prepared.report.blocking_reasons)
        )
    return prepared


def _artifact_parameters(artifact: ModelArtifact) -> FittedParameters:
    return FittedParameters(
        model_type=artifact.model_type,
        alpha=artifact.alpha,
        class_log_priors=artifact.class_log_priors,
        feature_log_probabilities=artifact.feature_log_probabilities,
        feature_log_complements=artifact.feature_log_complements,
        class_counts=artifact.class_counts,
    )


def _benchmark_fields(
    provenance: BenchmarkProvenance | None,
) -> tuple[str, int | None, str | None, str | None]:
    if provenance is None:
        return "reviewed_observations", None, None, None
    return (
        "controlled_benchmark",
        provenance.run_id,
        provenance.catalog_version,
        provenance.manifest_sha256,
    )


def train_baseline(
    examples: tuple[TrainingExample, ...],
    *,
    minimum_samples: int = 20,
    minimum_per_class: int = 5,
    minimum_scans: int = 4,
    minimum_scans_per_class: int = 2,
    test_fraction: float = 0.2,
    random_seed: int = 42,
    alpha: float = 1.0,
    maximum_tokens: int = 128,
    benchmark_provenance: BenchmarkProvenance | None = None,
) -> ModelArtifact:
    """Train the original Multinomial baseline with scan-isolated evaluation."""
    prepared = _prepare_dataset(
        examples,
        minimum_samples=minimum_samples,
        minimum_per_class=minimum_per_class,
        minimum_scans=minimum_scans,
        minimum_scans_per_class=minimum_scans_per_class,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )
    canonical_examples = prepared.examples
    train_examples, holdout_examples = split_by_scan_groups(
        canonical_examples,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )
    schema = build_feature_schema(train_examples, maximum_tokens=maximum_tokens)
    train_vectors = vectorize_many(train_examples, schema)
    if not train_vectors or not train_vectors[0]:
        raise ModelArtifactError("Feature engineering produced an empty model input.")

    parameters = fit_model(
        train_examples,
        train_vectors,
        model_type="multinomial_naive_bayes",
        alpha=alpha,
    )
    holdout_predictions = tuple(
        predict_vector(
            vectorize(example, schema),
            parameters=parameters,
            decision_threshold=0.5,
        )
        for example in holdout_examples
    )
    evaluation = evaluate_predictions(holdout_examples, holdout_predictions)
    training_context, run_id, catalog_version, manifest_digest = _benchmark_fields(
        benchmark_provenance
    )

    return ModelArtifact(
        created_at=datetime.now(UTC),
        application_version=__version__,
        random_seed=random_seed,
        alpha=alpha,
        decision_threshold=0.5,
        training_samples=len(train_examples),
        holdout_samples=len(holdout_examples),
        class_counts=parameters.class_counts,
        dataset_sha256=dataset_sha256(canonical_examples),
        feature_schema=schema,
        class_log_priors=parameters.class_log_priors,
        feature_log_probabilities=parameters.feature_log_probabilities,
        feature_log_complements={},
        evaluation=evaluation,
        source_samples=prepared.report.source_samples,
        deduplicated_samples=prepared.report.unique_samples,
        duplicate_samples_removed=prepared.report.duplicate_samples,
        split_strategy="scan_group_stratified",
        training_scan_ids=tuple(sorted({example.scan_id for example in train_examples})),
        holdout_scan_ids=tuple(sorted({example.scan_id for example in holdout_examples})),
        artifact_version=3 if benchmark_provenance is not None else 2,
        training_context=training_context,
        benchmark_run_id=run_id,
        benchmark_catalog_version=catalog_version,
        benchmark_manifest_sha256=manifest_digest,
    )


def train_tuned(
    examples: tuple[TrainingExample, ...],
    *,
    minimum_samples: int = 20,
    minimum_per_class: int = 5,
    minimum_scans: int = 6,
    minimum_scans_per_class: int = 3,
    test_fraction: float = 0.2,
    random_seed: int = 42,
    maximum_tokens: int = 128,
    benchmark_provenance: BenchmarkProvenance | None = None,
) -> ModelArtifact:
    """Tune only on training scans, then evaluate once on untouched holdout scans."""
    prepared = _prepare_dataset(
        examples,
        minimum_samples=minimum_samples,
        minimum_per_class=minimum_per_class,
        minimum_scans=minimum_scans,
        minimum_scans_per_class=minimum_scans_per_class,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )
    canonical_examples = prepared.examples
    train_examples, holdout_examples = split_by_scan_groups(
        canonical_examples,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )

    selection = tune_model(
        train_examples,
        maximum_tokens=maximum_tokens,
    )
    schema = build_feature_schema(train_examples, maximum_tokens=maximum_tokens)
    train_vectors = vectorize_many(train_examples, schema)
    if not train_vectors or not train_vectors[0]:
        raise ModelArtifactError("Feature engineering produced an empty model input.")

    parameters = fit_model(
        train_examples,
        train_vectors,
        model_type=selection.model_type,
        alpha=selection.alpha,
    )
    holdout_predictions = tuple(
        predict_vector(
            vectorize(example, schema),
            parameters=parameters,
            decision_threshold=selection.decision_threshold,
        )
        for example in holdout_examples
    )
    evaluation = evaluate_predictions(holdout_examples, holdout_predictions)
    training_context, run_id, catalog_version, manifest_digest = _benchmark_fields(
        benchmark_provenance
    )

    return ModelArtifact(
        artifact_version=4,
        model_type=selection.model_type,
        created_at=datetime.now(UTC),
        application_version=__version__,
        random_seed=random_seed,
        alpha=selection.alpha,
        decision_threshold=selection.decision_threshold,
        training_samples=len(train_examples),
        holdout_samples=len(holdout_examples),
        class_counts=parameters.class_counts,
        dataset_sha256=dataset_sha256(canonical_examples),
        feature_schema=schema,
        class_log_priors=parameters.class_log_priors,
        feature_log_probabilities=parameters.feature_log_probabilities,
        feature_log_complements=parameters.feature_log_complements,
        evaluation=evaluation,
        source_samples=prepared.report.source_samples,
        deduplicated_samples=prepared.report.unique_samples,
        duplicate_samples_removed=prepared.report.duplicate_samples,
        split_strategy="scan_group_stratified",
        training_scan_ids=tuple(sorted({example.scan_id for example in train_examples})),
        holdout_scan_ids=tuple(sorted({example.scan_id for example in holdout_examples})),
        training_context=training_context,
        benchmark_run_id=run_id,
        benchmark_catalog_version=catalog_version,
        benchmark_manifest_sha256=manifest_digest,
        tuning=selection.summary,
    )


def predict(example: ObservationInput, artifact: ModelArtifact) -> Prediction:
    """Predict one observation using a validated model artifact."""
    vector = vectorize(example, artifact.feature_schema)
    expected_features = len(artifact.feature_schema.feature_names)
    if len(vector) != expected_features:
        raise ModelArtifactError("The feature vector does not match the model schema.")

    return predict_vector(
        vector,
        parameters=_artifact_parameters(artifact),
        decision_threshold=artifact.decision_threshold,
    )


def save_model(artifact: ModelArtifact, output_path: Path) -> None:
    """Atomically persist a private model JSON artifact."""
    resolved_path = output_path.expanduser().resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = resolved_path.with_suffix(resolved_path.suffix + ".tmp")

    try:
        payload = artifact.model_dump_json(indent=2).encode("utf-8")
        if len(payload) > _MAXIMUM_MODEL_BYTES:
            raise ModelArtifactError("The generated model exceeds the 10 MiB safety limit.")

        with temporary_path.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, resolved_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def load_model(model_path: Path) -> ModelArtifact:
    """Load and validate a bounded model artifact without executing code."""
    resolved_path = model_path.expanduser().resolve()

    try:
        size = resolved_path.stat().st_size
    except OSError as exc:
        raise ModelArtifactError(f"Unable to read model artifact: {exc}") from exc

    if size > _MAXIMUM_MODEL_BYTES:
        raise ModelArtifactError("The model artifact exceeds the 10 MiB safety limit.")

    try:
        payload = resolved_path.read_text(encoding="utf-8")
        artifact = ModelArtifact.model_validate_json(payload)
    except (OSError, UnicodeError, ValidationError, json.JSONDecodeError) as exc:
        raise ModelArtifactError("The model artifact is malformed or incompatible.") from exc

    feature_count = len(artifact.feature_schema.feature_names)
    for label in artifact.labels:
        if len(artifact.feature_log_probabilities[label]) != feature_count:
            raise ModelArtifactError("The model artifact has inconsistent feature dimensions.")
        if (
            artifact.model_type == "bernoulli_naive_bayes"
            and len(artifact.feature_log_complements[label]) != feature_count
        ):
            raise ModelArtifactError("The model artifact has inconsistent complement dimensions.")

    return artifact
