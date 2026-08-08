"""Development-only leakage and feature-ablation evaluation contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.ml.estimators import evaluate_predictions, fit_model, predict_vector
from vulnhunter.ml.feature_extractors import default_feature_extractor
from vulnhunter.ml.models import EvaluationMetrics, ModelType, TrainingExample

AblationName = Literal[
    "full_baseline",
    "structural_evidence_only",
    "no_category",
    "no_severity",
    "no_title_description_tokens",
]
GroupAblationKind = Literal[
    "category",
    "detector",
    "template_family",
    "application_family",
]


class AblationEvaluationError(RuntimeError):
    """A leakage-evaluation invariant failed closed."""


class FeatureAblationResult(BaseModel):
    """Metrics for one declared feature-family ablation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: AblationName
    feature_count: int = Field(ge=1)
    training_samples: int = Field(ge=2)
    validation_samples: int = Field(ge=1)
    metrics: EvaluationMetrics


class GroupHoldoutSlice(BaseModel):
    """One leave-one-group-out development slice."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    group_kind: GroupAblationKind
    group_key: str = Field(min_length=1, max_length=200)
    training_samples: int = Field(ge=2)
    validation_samples: int = Field(ge=1)
    metrics: EvaluationMetrics


class GroupAblationReport(BaseModel):
    """Truthful leave-one-group-out report or explicit unavailable reason."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    group_kind: GroupAblationKind
    available: bool
    reason: str | None = Field(default=None, max_length=500)
    slices: tuple[GroupHoldoutSlice, ...] = ()

    @model_validator(mode="after")
    def availability_matches_content(self) -> GroupAblationReport:
        if self.available:
            if not self.slices or self.reason is not None:
                raise ValueError("available group ablation requires slices and no reason")
        elif self.reason is None or self.slices:
            raise ValueError("unavailable group ablation requires one reason and no slices")
        return self


class LeakageAblationReport(BaseModel):
    """Development-only leakage report; never external-holdout evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task: Literal["review_priority"] = "review_priority"
    evaluation_scope: Literal["development_only"] = "development_only"
    feature_ablations: tuple[FeatureAblationResult, ...]
    group_ablations: tuple[GroupAblationReport, ...]
    external_holdout_used: Literal[False] = False


def _indices(names: tuple[str, ...], ablation: AblationName) -> tuple[int, ...]:
    selected: list[int] = []
    for index, name in enumerate(names):
        keep = True
        if ablation == "structural_evidence_only":
            keep = name.startswith(("url:", "evidence:"))
        elif ablation == "no_category":
            keep = not name.startswith("category:")
        elif ablation == "no_severity":
            keep = not name.startswith("severity:")
        elif ablation == "no_title_description_tokens":
            keep = not name.startswith("token:")
        if keep:
            selected.append(index)
    if not selected:
        raise AblationEvaluationError(f"{ablation} removed every feature")
    return tuple(selected)


def _subset(vector: tuple[float, ...], indices: tuple[int, ...]) -> tuple[float, ...]:
    return tuple(vector[index] for index in indices)


def _evaluate(
    training: Sequence[TrainingExample],
    validation: Sequence[TrainingExample],
    *,
    model_type: ModelType,
    alpha: float,
    decision_threshold: float,
    maximum_tokens: int,
    ablation: AblationName,
) -> FeatureAblationResult:
    if len(training) < 2 or not validation:
        raise AblationEvaluationError("ablation evaluation requires training and validation data")
    if len({item.label for item in training}) != 2:
        raise AblationEvaluationError("ablation training data must contain both human labels")

    extractor = default_feature_extractor()
    schema = extractor.build_schema(training, maximum_tokens=maximum_tokens)
    names = schema.feature_names
    indices = _indices(names, ablation)
    train_vectors = tuple(_subset(extractor.extract(item, schema).vector, indices) for item in training)
    validation_vectors = tuple(
        _subset(extractor.extract(item, schema).vector, indices) for item in validation
    )
    parameters = fit_model(training, train_vectors, model_type=model_type, alpha=alpha)
    predictions = tuple(
        predict_vector(
            vector,
            parameters=parameters,
            decision_threshold=decision_threshold,
        )
        for vector in validation_vectors
    )
    return FeatureAblationResult(
        name=ablation,
        feature_count=len(indices),
        training_samples=len(training),
        validation_samples=len(validation),
        metrics=evaluate_predictions(tuple(validation), predictions),
    )


def evaluate_feature_ablations(
    training: Sequence[TrainingExample],
    validation: Sequence[TrainingExample],
    *,
    model_type: ModelType = "multinomial_naive_bayes",
    alpha: float = 1.0,
    decision_threshold: float = 0.5,
    maximum_tokens: int = 128,
) -> tuple[FeatureAblationResult, ...]:
    """Compare the required feature-family baselines using development data only."""

    names: tuple[AblationName, ...] = (
        "full_baseline",
        "structural_evidence_only",
        "no_category",
        "no_severity",
        "no_title_description_tokens",
    )
    return tuple(
        _evaluate(
            training,
            validation,
            model_type=model_type,
            alpha=alpha,
            decision_threshold=decision_threshold,
            maximum_tokens=maximum_tokens,
            ablation=name,
        )
        for name in names
    )


def evaluate_leave_one_group_out(
    examples: Sequence[TrainingExample],
    *,
    group_kind: GroupAblationKind,
    group_keys: Mapping[int, str] | None = None,
    model_type: ModelType = "multinomial_naive_bayes",
    alpha: float = 1.0,
    decision_threshold: float = 0.5,
    maximum_tokens: int = 128,
) -> GroupAblationReport:
    """Evaluate whole held-out groups without inventing unavailable provenance."""

    if group_kind == "category":
        keys = {item.observation_id: item.category for item in examples}
    elif group_keys is None:
        return GroupAblationReport(
            group_kind=group_kind,
            available=False,
            reason=f"{group_kind} provenance is not available for these development examples",
        )
    else:
        keys = dict(group_keys)

    missing = [item.observation_id for item in examples if not keys.get(item.observation_id)]
    if missing:
        return GroupAblationReport(
            group_kind=group_kind,
            available=False,
            reason=f"{group_kind} provenance is incomplete for the supplied development examples",
        )

    unique = tuple(sorted({keys[item.observation_id] for item in examples}))
    if len(unique) < 2:
        return GroupAblationReport(
            group_kind=group_kind,
            available=False,
            reason=f"{group_kind} evaluation requires at least two distinct groups",
        )

    slices: list[GroupHoldoutSlice] = []
    for held_out in unique:
        validation = tuple(item for item in examples if keys[item.observation_id] == held_out)
        training = tuple(item for item in examples if keys[item.observation_id] != held_out)
        if len(training) < 2 or len({item.label for item in training}) != 2:
            return GroupAblationReport(
                group_kind=group_kind,
                available=False,
                reason=(
                    f"{group_kind} leave-one-group-out cannot preserve both labels in every "
                    "development training fold"
                ),
            )
        result = _evaluate(
            training,
            validation,
            model_type=model_type,
            alpha=alpha,
            decision_threshold=decision_threshold,
            maximum_tokens=maximum_tokens,
            ablation="full_baseline",
        )
        slices.append(
            GroupHoldoutSlice(
                group_kind=group_kind,
                group_key=held_out,
                training_samples=len(training),
                validation_samples=len(validation),
                metrics=result.metrics,
            )
        )
    return GroupAblationReport(group_kind=group_kind, available=True, slices=tuple(slices))


def build_leakage_ablation_report(
    training: Sequence[TrainingExample],
    validation: Sequence[TrainingExample],
    *,
    development_examples: Sequence[TrainingExample],
    detector_keys: Mapping[int, str] | None = None,
    template_family_keys: Mapping[int, str] | None = None,
    application_family_keys: Mapping[int, str] | None = None,
) -> LeakageAblationReport:
    """Build the bounded P3.6 report without touching any external holdout."""

    groups = (
        evaluate_leave_one_group_out(development_examples, group_kind="category"),
        evaluate_leave_one_group_out(
            development_examples,
            group_kind="detector",
            group_keys=detector_keys,
        ),
        evaluate_leave_one_group_out(
            development_examples,
            group_kind="template_family",
            group_keys=template_family_keys,
        ),
        evaluate_leave_one_group_out(
            development_examples,
            group_kind="application_family",
            group_keys=application_family_keys,
        ),
    )
    return LeakageAblationReport(
        feature_ablations=evaluate_feature_ablations(training, validation),
        group_ablations=groups,
    )


__all__ = [
    "AblationEvaluationError",
    "FeatureAblationResult",
    "GroupAblationReport",
    "GroupHoldoutSlice",
    "LeakageAblationReport",
    "build_leakage_ablation_report",
    "evaluate_feature_ablations",
    "evaluate_leave_one_group_out",
]
