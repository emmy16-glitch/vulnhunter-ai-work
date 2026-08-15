"""Governed controlled-lab corpus lifecycle for Source Hunt benchmarks."""

from __future__ import annotations

import re

from pydantic import model_validator

from vulnhunter.source_hunt import controlled_corpus_models as _models
from vulnhunter.source_hunt.controlled_corpus_service import (
    ControlledBenchmarkCampaignRunner,
    ControlledCorpusDraftBuilder,
    ControlledCorpusReleaseService,
    ReviewedSourceBenchmarkSuiteBuilder,
)

ControlledFixtureFile = _models.ControlledFixtureFile
ControlledGroundTruthCase = _models.ControlledGroundTruthCase
ControlledGroundTruthSpec = _models.ControlledGroundTruthSpec
CorpusReviewerBinding = _models.CorpusReviewerBinding
CorpusReviewVerdict = _models.CorpusReviewVerdict

_DRAFT_ID_PATTERN = re.compile(r"^source-corpus-draft-[0-9a-f]{24}$")


def _require_safe_draft_id(draft_id: str) -> None:
    if _DRAFT_ID_PATTERN.fullmatch(draft_id) is None:
        raise ValueError("controlled-corpus draft identifier is invalid")


def _require_non_production_artifact(value: object, label: str) -> None:
    if getattr(value, "production_accuracy_claim_permitted", False):
        raise ValueError(f"{label} cannot permit production accuracy claims")


def _validate_release_governance(release: _models.ControlledCorpusRelease) -> None:
    _require_non_production_artifact(release, "controlled-corpus release")
    _require_non_production_artifact(release.draft, "controlled-corpus draft")

    bindings = {item.reviewer_id: item for item in release.draft.assigned_reviewers}
    if release.released_by == release.draft.prepared_by or release.released_by in bindings:
        raise ValueError("corpus releaser must be independent from preparer and reviewers")

    for review in release.reviews:
        binding = bindings.get(review.reviewer_id)
        if binding is None:
            raise ValueError("controlled-corpus release contains an unassigned reviewer")
        if review.draft_id != release.draft.draft_id:
            raise ValueError("controlled-corpus review is bound to a different draft identifier")
        if review.draft_sha256 != release.draft.draft_sha256:
            raise ValueError("controlled-corpus review is bound to a different draft digest")
        if review.reviewer_identity_sha256 != binding.identity_record_sha256:
            raise ValueError("controlled-corpus review identity does not match its assignment")


def _validate_suite_governance(suite_release: _models.ReviewedSourceBenchmarkSuite) -> None:
    _require_non_production_artifact(suite_release, "reviewed benchmark suite")
    for release in suite_release.corpus_releases:
        _validate_release_governance(release)


class ControlledCorpusDraft(_models.ControlledCorpusDraft):
    """Operational draft loader with non-production invariants enforced."""

    @model_validator(mode="after")
    def enforce_governance_invariants(self) -> ControlledCorpusDraft:
        _require_non_production_artifact(self, "controlled-corpus draft")
        return self


class CorpusReviewAttestation(_models.CorpusReviewAttestation):
    """Operational review loader that forbids path-like draft identifiers."""

    @model_validator(mode="after")
    def enforce_safe_draft_identifier(self) -> CorpusReviewAttestation:
        _require_safe_draft_id(self.draft_id)
        return self


class CorpusReviewLedger(_models.CorpusReviewLedger):
    """Review ledger hardened against draft-id path traversal."""

    def _path(self, draft_id: str, reviewer_id: str):
        _require_safe_draft_id(draft_id)
        return super()._path(draft_id, reviewer_id)


class ControlledCorpusRelease(_models.ControlledCorpusRelease):
    """Operational release loader that replays governance bindings on load."""

    @model_validator(mode="after")
    def enforce_governance_invariants(self) -> ControlledCorpusRelease:
        _validate_release_governance(self)
        return self


class ReviewedSourceBenchmarkSuite(_models.ReviewedSourceBenchmarkSuite):
    """Operational suite loader that recursively revalidates controlled releases."""

    @model_validator(mode="after")
    def enforce_governance_invariants(self) -> ReviewedSourceBenchmarkSuite:
        _validate_suite_governance(self)
        return self


class ControlledBenchmarkCampaignEvidence(_models.ControlledBenchmarkCampaignEvidence):
    """Operational campaign loader with recursive non-production guarantees."""

    @model_validator(mode="after")
    def enforce_governance_invariants(self) -> ControlledBenchmarkCampaignEvidence:
        _require_non_production_artifact(self, "controlled benchmark campaign evidence")
        _validate_suite_governance(self.suite_release)
        return self


__all__ = [
    "ControlledBenchmarkCampaignEvidence",
    "ControlledBenchmarkCampaignRunner",
    "ControlledCorpusDraft",
    "ControlledCorpusDraftBuilder",
    "ControlledCorpusRelease",
    "ControlledCorpusReleaseService",
    "ControlledFixtureFile",
    "ControlledGroundTruthCase",
    "ControlledGroundTruthSpec",
    "CorpusReviewAttestation",
    "CorpusReviewLedger",
    "CorpusReviewVerdict",
    "CorpusReviewerBinding",
    "ReviewedSourceBenchmarkSuite",
    "ReviewedSourceBenchmarkSuiteBuilder",
]
