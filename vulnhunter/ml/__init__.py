"""Reviewed-dataset and lightweight baseline machine-learning pipeline."""

from vulnhunter.ml.dataset import (
    build_dataset,
    dataset_sha256,
    export_jsonl,
    to_model_input,
)
from vulnhunter.ml.features import build_feature_schema, vectorize
from vulnhunter.ml.models import (
    EvaluationMetrics,
    FeatureSchema,
    ModelArtifact,
    ObservationInput,
    Prediction,
    TrainingExample,
    TrainingLabel,
)
from vulnhunter.ml.training import load_model, predict, save_model, train_baseline

__all__ = [
    "EvaluationMetrics",
    "FeatureSchema",
    "ModelArtifact",
    "ObservationInput",
    "Prediction",
    "TrainingExample",
    "TrainingLabel",
    "build_dataset",
    "build_feature_schema",
    "dataset_sha256",
    "export_jsonl",
    "load_model",
    "predict",
    "save_model",
    "to_model_input",
    "train_baseline",
    "vectorize",
]
