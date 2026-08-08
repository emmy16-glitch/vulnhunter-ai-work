"""Governed ML label ontology and task separation contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.ml.models import TrainingExample

ReviewState = Literal[
    "unreviewed",
    "awaiting_second_review",
    "review_disagreement",
    "awaiting_adjudication",
    "confirmed",
    "false_positive",
    "withdrawn",
    "corrected",
]
TerminalReviewLabel = Literal["confirmed", "false_positive"]
MLTaskName = Literal[
    "review_priority",
    "vulnerability_category",
    "severity_assistance",
    "related_finding_retrieval",
    "evidence_quality",
    "remediation_retrieval",
    "source_code_candidate_retrieval",
    "summarisation",
    "report_drafting",
]


class TaskContractError(RuntimeError):
    """A governed label or ML task invariant failed closed."""


class ReviewLabelContract(BaseModel):
    """Human-owned review state kept explicitly separate from model outputs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    review_state: ReviewState
    review_label: TerminalReviewLabel | None = None
    correction_reference: str | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def terminal_label_matches_state(self) -> Self:
        if self.review_state in {"confirmed", "false_positive"}:
            if self.review_label != self.review_state:
                raise ValueError("terminal review state requires its matching human label")
        elif self.review_label is not None:
            raise ValueError("non-terminal review state cannot expose a terminal review label")
        if self.review_state in {"withdrawn", "corrected"} and self.correction_reference is None:
            raise ValueError("withdrawn or corrected review state requires provenance")
        if (
            self.review_state not in {"withdrawn", "corrected"}
            and self.correction_reference is not None
        ):
            raise ValueError("correction provenance is valid only for withdrawn or corrected state")
        return self

    @property
    def eligible_for_binary_training(self) -> bool:
        return self.review_state in {"confirmed", "false_positive"}


class MLTaskContract(BaseModel):
    """One versioned task with its own target, metrics and authority boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task: MLTaskName
    schema_version: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=200)
    metrics: tuple[str, ...] = Field(min_length=1)
    requires_terminal_review_label: bool = False
    output_semantics: str = Field(min_length=1, max_length=500)
    advisory_only: Literal[True] = True

    @model_validator(mode="after")
    def metrics_are_explicit(self) -> Self:
        normalized = tuple(metric.strip() for metric in self.metrics)
        if any(not metric for metric in normalized) or len(set(normalized)) != len(normalized):
            raise ValueError("task metrics must be explicit and unique")
        if "confidence" in {metric.lower() for metric in normalized}:
            raise ValueError("generic confidence is not a valid cross-task metric")
        return self


TASK_CONTRACTS: dict[MLTaskName, MLTaskContract] = {
    "review_priority": MLTaskContract(
        task="review_priority",
        schema_version="review-priority-v1",
        target="confirmed versus false-positive review priority",
        metrics=("precision", "recall", "pr_auc", "review_budget_recall"),
        requires_terminal_review_label=True,
        output_semantics="Suggested review priority only; human review remains authoritative.",
    ),
    "vulnerability_category": MLTaskContract(
        task="vulnerability_category",
        schema_version="vulnerability-category-v1",
        target="reviewed vulnerability category",
        metrics=("macro_f1", "per_class_recall"),
        requires_terminal_review_label=True,
        output_semantics="Advisory category suggestion for a human reviewer.",
    ),
    "severity_assistance": MLTaskContract(
        task="severity_assistance",
        schema_version="severity-assistance-v1",
        target="reviewer-facing severity assistance",
        metrics=("macro_f1", "weighted_kappa"),
        requires_terminal_review_label=True,
        output_semantics=(
            "Advisory severity assistance; never changes persisted severity authority."
        ),
    ),
    "related_finding_retrieval": MLTaskContract(
        task="related_finding_retrieval",
        schema_version="related-finding-retrieval-v1",
        target="duplicate or related finding retrieval",
        metrics=("recall_at_k", "mrr"),
        output_semantics="Retrieval ranking only; no duplicate decision authority.",
    ),
    "evidence_quality": MLTaskContract(
        task="evidence_quality",
        schema_version="evidence-quality-v1",
        target="evidence quality scoring",
        metrics=("spearman", "mae"),
        output_semantics="Advisory evidence-quality estimate only.",
    ),
    "remediation_retrieval": MLTaskContract(
        task="remediation_retrieval",
        schema_version="remediation-retrieval-v1",
        target="relevant remediation retrieval",
        metrics=("recall_at_k", "mrr"),
        output_semantics="Retrieval ranking only; remediation remains reviewable guidance.",
    ),
    "source_code_candidate_retrieval": MLTaskContract(
        task="source_code_candidate_retrieval",
        schema_version="source-code-candidate-retrieval-v1",
        target="source-code vulnerability candidate retrieval",
        metrics=("recall_at_k", "mrr"),
        output_semantics="Candidate retrieval only; no vulnerability confirmation authority.",
    ),
    "summarisation": MLTaskContract(
        task="summarisation",
        schema_version="summarisation-v1",
        target="evidence-grounded natural-language summary",
        metrics=("citation_coverage", "factuality_review_rate"),
        output_semantics="Draft summary only; persisted evidence remains authoritative.",
    ),
    "report_drafting": MLTaskContract(
        task="report_drafting",
        schema_version="report-drafting-v1",
        target="evidence-grounded report draft",
        metrics=("citation_coverage", "human_acceptance_rate"),
        output_semantics=(
            "Draft report text only; publication and review authority remain separate."
        ),
    ),
}


class AdvisoryTaskResult(BaseModel):
    """Task-scoped advisory result without pretending P3.7 calibration exists."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str = Field(min_length=1, max_length=200)
    model_version: str = Field(min_length=1, max_length=100)
    task: MLTaskName
    task_schema_version: str = Field(min_length=1, max_length=100)
    output: dict[str, object]
    reason_codes: tuple[str, ...] = ()
    created_at: datetime
    advisory_only: Literal[True] = True

    @model_validator(mode="after")
    def task_schema_matches_registry(self) -> Self:
        contract = TASK_CONTRACTS[self.task]
        if self.task_schema_version != contract.schema_version:
            raise ValueError(
                "advisory result task schema does not match the governed task contract"
            )
        forbidden = {
            "review_label",
            "effective_label",
            "positive_probability_calibrated",
            "uncertainty",
            "out_of_distribution_score",
        }
        if forbidden.intersection(self.output):
            raise ValueError(
                "advisory result cannot claim human labels or unimplemented P3.7 fields"
            )
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("advisory result timestamp must include a timezone")
        return self.model_copy(update={"created_at": self.created_at.astimezone(UTC)})


def require_binary_training_label(
    example: TrainingExample,
    review: ReviewLabelContract,
) -> TrainingExample:
    """Allow the binary task to consume only matching eligible terminal human labels."""

    if not review.eligible_for_binary_training or review.review_label is None:
        raise TaskContractError(
            "binary production training requires an eligible terminal human label"
        )
    if example.label != review.review_label:
        raise TaskContractError(
            "training example label does not match authoritative human review label"
        )
    return example


def task_contract(task: MLTaskName) -> MLTaskContract:
    """Return the canonical task-specific contract."""

    return TASK_CONTRACTS[task]


__all__ = [
    "AdvisoryTaskResult",
    "MLTaskContract",
    "MLTaskName",
    "ReviewLabelContract",
    "ReviewState",
    "TASK_CONTRACTS",
    "TaskContractError",
    "TerminalReviewLabel",
    "require_binary_training_label",
    "task_contract",
]
