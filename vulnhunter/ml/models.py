"""Validated dataset, feature, model, tuning, and evaluation contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

TrainingLabel = Literal["confirmed", "false_positive"]
ModelType = Literal["multinomial_naive_bayes", "bernoulli_naive_bayes"]


class ObservationInput(BaseModel):
    """Sanitised observation fields accepted by feature engineering."""

    model_config = ConfigDict(frozen=True)

    observation_id: int = Field(ge=1)
    scan_id: int = Field(ge=1)
    category: str = Field(min_length=1, max_length=100)
    severity: Literal["info", "low", "medium", "high"]
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)
    url: str = Field(min_length=1, max_length=2_000)
    evidence: dict[str, object] = Field(default_factory=dict)
    fingerprint: str = Field(min_length=64, max_length=64)


class TrainingExample(ObservationInput):
    """One human-reviewed observation eligible for supervised training."""

    label: TrainingLabel


class FeatureSchema(BaseModel):
    """Deterministic feature vocabulary used by one trained model."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal[1, 2] = 1
    categories: tuple[str, ...] = ()
    tokens: tuple[str, ...] = ()
    fixed_features: tuple[str, ...]

    @model_validator(mode="after")
    def validate_schema(self) -> FeatureSchema:
        """Reject ambiguous or non-deterministic feature schemas."""
        for name, values in (
            ("categories", self.categories),
            ("tokens", self.tokens),
            ("fixed_features", self.fixed_features),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must not contain duplicates.")

        if tuple(sorted(self.categories)) != self.categories:
            raise ValueError("categories must be sorted.")

        if not self.fixed_features:
            raise ValueError("fixed_features must not be empty.")

        return self

    @property
    def feature_names(self) -> tuple[str, ...]:
        """Return the complete feature order used by the model."""
        severity_features = tuple(
            f"severity:{value}" for value in ("info", "low", "medium", "high")
        )
        category_features = tuple(f"category:{value}" for value in self.categories)
        token_features = tuple(f"token:{value}" for value in self.tokens)
        return severity_features + category_features + token_features + self.fixed_features


class Prediction(BaseModel):
    """Binary model prediction with normalised posterior confidence."""

    model_config = ConfigDict(frozen=True, allow_inf_nan=False)

    label: TrainingLabel
    confidence: float = Field(ge=0, le=1)
    probabilities: dict[TrainingLabel, float]


class EvaluationMetrics(BaseModel):
    """Evaluation metrics for the positive `confirmed` class."""

    model_config = ConfigDict(frozen=True, allow_inf_nan=False)

    test_samples: int = Field(ge=1)
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    accuracy: float = Field(ge=0, le=1)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1_score: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def validate_confusion_total(self) -> EvaluationMetrics:
        total = self.true_positive + self.false_positive + self.true_negative + self.false_negative
        if total != self.test_samples:
            raise ValueError("Confusion-matrix counts must sum to test_samples.")
        return self


class TuningSummary(BaseModel):
    """Training-only grouped cross-validation selection provenance."""

    model_config = ConfigDict(frozen=True, allow_inf_nan=False)

    selection_metric: Literal["f1"] = "f1"
    fold_count: int = Field(ge=2)
    candidate_count: int = Field(ge=1)
    algorithm_candidates: tuple[ModelType, ...]
    alpha_candidates: tuple[float, ...]
    threshold_candidates: tuple[float, ...]
    selected_model_type: ModelType
    selected_alpha: float = Field(gt=0, le=100)
    selected_threshold: float = Field(gt=0, lt=1)
    cross_validation: EvaluationMetrics

    @model_validator(mode="after")
    def validate_selection(self) -> TuningSummary:
        if len(self.algorithm_candidates) != len(set(self.algorithm_candidates)):
            raise ValueError("algorithm_candidates must not contain duplicates.")
        if len(self.alpha_candidates) != len(set(self.alpha_candidates)):
            raise ValueError("alpha_candidates must not contain duplicates.")
        if len(self.threshold_candidates) != len(set(self.threshold_candidates)):
            raise ValueError("threshold_candidates must not contain duplicates.")
        if self.selected_model_type not in self.algorithm_candidates:
            raise ValueError("selected_model_type must be one of algorithm_candidates.")
        if self.selected_alpha not in self.alpha_candidates:
            raise ValueError("selected_alpha must be one of alpha_candidates.")
        if self.selected_threshold not in self.threshold_candidates:
            raise ValueError("selected_threshold must be one of threshold_candidates.")
        if any(value <= 0 or value > 100 for value in self.alpha_candidates):
            raise ValueError("alpha_candidates must be greater than zero and at most 100.")
        if any(value <= 0 or value >= 1 for value in self.threshold_candidates):
            raise ValueError("threshold_candidates must be between zero and one.")
        return self


class BenchmarkProvenance(BaseModel):
    """Integrity metadata identifying a controlled benchmark training run."""

    model_config = ConfigDict(frozen=True)

    run_id: str = Field(min_length=36, max_length=36)
    catalog_version: int = Field(ge=1)
    manifest_sha256: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def validate_digest(self) -> BenchmarkProvenance:
        try:
            int(self.manifest_sha256, 16)
        except ValueError as exc:
            raise ValueError("manifest_sha256 must be hexadecimal.") from exc
        return self


class ModelArtifact(BaseModel):
    """Portable, versioned Naive Bayes model artifact."""

    model_config = ConfigDict(frozen=True, allow_inf_nan=False)

    artifact_version: Literal[1, 2, 3, 4] = 2
    model_type: ModelType = "multinomial_naive_bayes"
    created_at: datetime
    application_version: str
    random_seed: int
    alpha: float = Field(gt=0, le=100)
    decision_threshold: float = Field(default=0.5, gt=0, lt=1)
    positive_label: Literal["confirmed"] = "confirmed"
    labels: tuple[TrainingLabel, TrainingLabel] = ("confirmed", "false_positive")
    training_samples: int = Field(ge=2)
    holdout_samples: int = Field(ge=2)
    class_counts: dict[TrainingLabel, int]
    dataset_sha256: str = Field(min_length=64, max_length=64)
    feature_schema: FeatureSchema
    class_log_priors: dict[TrainingLabel, float]
    feature_log_probabilities: dict[TrainingLabel, tuple[float, ...]]
    feature_log_complements: dict[TrainingLabel, tuple[float, ...]] = Field(default_factory=dict)
    evaluation: EvaluationMetrics

    source_samples: int = Field(default=0, ge=0)
    deduplicated_samples: int = Field(default=0, ge=0)
    duplicate_samples_removed: int = Field(default=0, ge=0)
    split_strategy: Literal["observation_stratified", "scan_group_stratified"] = (
        "observation_stratified"
    )
    training_scan_ids: tuple[int, ...] = ()
    holdout_scan_ids: tuple[int, ...] = ()

    training_context: Literal[
        "reviewed_observations",
        "controlled_benchmark",
    ] = "reviewed_observations"
    benchmark_run_id: str | None = None
    benchmark_catalog_version: int | None = Field(default=None, ge=1)
    benchmark_manifest_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    tuning: TuningSummary | None = None

    @model_validator(mode="after")
    def validate_artifact(self) -> ModelArtifact:
        """Validate internal dimensions, split isolation, and provenance."""
        expected_labels = ("confirmed", "false_positive")
        expected_label_set = set(expected_labels)

        if self.labels != expected_labels:
            raise ValueError("labels must be ('confirmed', 'false_positive').")

        if set(self.class_counts) != expected_label_set:
            raise ValueError("class_counts must contain both model labels.")

        if sum(self.class_counts.values()) != self.training_samples:
            raise ValueError("class_counts must sum to training_samples.")

        if any(count < 1 for count in self.class_counts.values()):
            raise ValueError("Both model classes must contain training samples.")

        if set(self.class_log_priors) != expected_label_set:
            raise ValueError("class_log_priors must contain both model labels.")

        if set(self.feature_log_probabilities) != expected_label_set:
            raise ValueError("feature_log_probabilities must contain both model labels.")

        feature_count = len(self.feature_schema.feature_names)
        if feature_count < 1:
            raise ValueError("The model must contain at least one feature.")

        if any(
            len(self.feature_log_probabilities[label]) != feature_count for label in expected_labels
        ):
            raise ValueError("Model feature dimensions are inconsistent.")

        if self.model_type == "bernoulli_naive_bayes":
            if set(self.feature_log_complements) != expected_label_set:
                raise ValueError("Bernoulli models require complement probabilities.")
            if any(
                len(self.feature_log_complements[label]) != feature_count
                for label in expected_labels
            ):
                raise ValueError("Bernoulli complement dimensions are inconsistent.")
        elif self.feature_log_complements:
            raise ValueError("Multinomial models must not store Bernoulli complements.")

        if self.evaluation.test_samples != self.holdout_samples:
            raise ValueError("Holdout sample counts are inconsistent.")

        try:
            int(self.dataset_sha256, 16)
        except ValueError as exc:
            raise ValueError("dataset_sha256 must be hexadecimal.") from exc

        if self.artifact_version >= 2:
            if self.source_samples < self.deduplicated_samples:
                raise ValueError("source_samples cannot be below deduplicated_samples.")

            if self.source_samples - self.deduplicated_samples != self.duplicate_samples_removed:
                raise ValueError("Duplicate provenance counts are inconsistent.")

            if self.deduplicated_samples != self.training_samples + self.holdout_samples:
                raise ValueError("Deduplicated sample counts are inconsistent.")

            if self.split_strategy != "scan_group_stratified":
                raise ValueError("Version 2+ artifacts require a scan-group split.")

            if not self.training_scan_ids or not self.holdout_scan_ids:
                raise ValueError("Version 2+ artifacts require train and holdout scans.")

            if set(self.training_scan_ids) & set(self.holdout_scan_ids):
                raise ValueError("Training and holdout scan IDs must be disjoint.")

            if tuple(sorted(set(self.training_scan_ids))) != self.training_scan_ids:
                raise ValueError("training_scan_ids must be sorted and unique.")

            if tuple(sorted(set(self.holdout_scan_ids))) != self.holdout_scan_ids:
                raise ValueError("holdout_scan_ids must be sorted and unique.")

        benchmark_fields = (
            self.benchmark_run_id,
            self.benchmark_catalog_version,
            self.benchmark_manifest_sha256,
        )
        if self.training_context == "controlled_benchmark":
            if self.artifact_version < 3:
                raise ValueError("Controlled benchmark artifacts require version 3 or newer.")
            if any(value is None for value in benchmark_fields):
                raise ValueError("Controlled benchmark artifacts require complete provenance.")
            try:
                int(self.benchmark_manifest_sha256 or "", 16)
            except ValueError as exc:
                raise ValueError("benchmark_manifest_sha256 must be hexadecimal.") from exc
        elif any(value is not None for value in benchmark_fields):
            raise ValueError("Benchmark provenance requires controlled benchmark context.")

        if self.artifact_version == 3:
            if self.model_type != "multinomial_naive_bayes":
                raise ValueError("Version 3 artifacts are Multinomial Naive Bayes baselines.")
            if self.tuning is not None:
                raise ValueError("Version 3 artifacts must not contain tuning provenance.")

        if self.artifact_version == 4:
            if self.feature_schema.schema_version != 2:
                raise ValueError("Version 4 artifacts require feature schema version 2.")
            if self.tuning is None:
                raise ValueError("Version 4 artifacts require tuning provenance.")
            if self.tuning.selected_model_type != self.model_type:
                raise ValueError("Tuning model type does not match the fitted model.")
            if self.tuning.selected_alpha != self.alpha:
                raise ValueError("Tuning alpha does not match the fitted model.")
            if self.tuning.selected_threshold != self.decision_threshold:
                raise ValueError("Tuning threshold does not match the fitted model.")
        elif self.tuning is not None:
            raise ValueError("Tuning provenance is only valid on version 4 artifacts.")

        if self.model_type == "bernoulli_naive_bayes" and self.artifact_version < 4:
            raise ValueError("Bernoulli models require artifact version 4.")

        return self
