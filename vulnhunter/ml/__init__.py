"""Reviewed-dataset and leakage-resistant baseline ML pipeline."""

from vulnhunter.ml.dataset import (
    build_dataset,
    dataset_sha256,
    export_jsonl,
    to_model_input,
)
from vulnhunter.ml.features import build_feature_schema, vectorize
from vulnhunter.ml.models import (
    BenchmarkProvenance,
    EvaluationMetrics,
    FeatureSchema,
    ModelArtifact,
    ObservationInput,
    Prediction,
    TrainingExample,
    TrainingLabel,
)
from vulnhunter.ml.quality import (
    DatasetQualityReport,
    PreparedTrainingDataset,
    assess_dataset_quality,
)
from vulnhunter.ml.splitting import split_by_scan_groups
from vulnhunter.ml.training import load_model, predict, save_model, train_baseline

__all__ = [
    "BenchmarkProvenance",
    "DatasetQualityReport",
    "EvaluationMetrics",
    "FeatureSchema",
    "ModelArtifact",
    "ObservationInput",
    "Prediction",
    "PreparedTrainingDataset",
    "TrainingExample",
    "TrainingLabel",
    "assess_dataset_quality",
    "build_dataset",
    "build_feature_schema",
    "dataset_sha256",
    "export_jsonl",
    "load_model",
    "predict",
    "save_model",
    "split_by_scan_groups",
    "to_model_input",
    "train_baseline",
    "vectorize",
]
