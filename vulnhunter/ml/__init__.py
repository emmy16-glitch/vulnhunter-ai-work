"""Reviewed-dataset and leakage-resistant local ML pipeline."""

from vulnhunter.ml.dataset import (
    build_dataset,
    dataset_sha256,
    export_jsonl,
    to_model_input,
)
from vulnhunter.ml.diagnostics import (
    DiagnosticCase,
    DiagnosticReport,
    DiagnosticSlice,
    diagnose_holdout,
)
from vulnhunter.ml.features import build_feature_schema, vectorize
from vulnhunter.ml.models import (
    BenchmarkProvenance,
    EvaluationMetrics,
    FeatureSchema,
    ModelArtifact,
    ModelType,
    ObservationInput,
    Prediction,
    TrainingExample,
    TrainingLabel,
    TuningSummary,
)
from vulnhunter.ml.quality import (
    DatasetQualityReport,
    PreparedTrainingDataset,
    assess_dataset_quality,
)
from vulnhunter.ml.splitting import split_by_scan_groups
from vulnhunter.ml.training import (
    load_model,
    predict,
    save_model,
    train_baseline,
    train_tuned,
)
from vulnhunter.ml.tuning import (
    GroupFold,
    TuningResult,
    build_two_fold_group_cv,
    tune_model,
)

__all__ = [
    "BenchmarkProvenance",
    "DatasetQualityReport",
    "DiagnosticCase",
    "DiagnosticReport",
    "DiagnosticSlice",
    "EvaluationMetrics",
    "FeatureSchema",
    "GroupFold",
    "ModelArtifact",
    "ModelType",
    "ObservationInput",
    "Prediction",
    "PreparedTrainingDataset",
    "TrainingExample",
    "TrainingLabel",
    "TuningResult",
    "TuningSummary",
    "assess_dataset_quality",
    "build_dataset",
    "build_feature_schema",
    "build_two_fold_group_cv",
    "dataset_sha256",
    "diagnose_holdout",
    "export_jsonl",
    "load_model",
    "predict",
    "save_model",
    "split_by_scan_groups",
    "to_model_input",
    "train_baseline",
    "train_tuned",
    "tune_model",
    "vectorize",
]
