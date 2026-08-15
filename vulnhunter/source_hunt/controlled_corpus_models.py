"""Governed controlled-lab corpus lifecycle for Source Hunt benchmarks."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.governance.models import ReviewerIdentity
from vulnhunter.source_hunt.benchmark_acceptance import (
    SourceBenchmarkAcceptanceBundle,
    SourceBenchmarkAcceptancePolicy,
    SourceBenchmarkSuite,
    SourceBenchmarkSuiteEntry,
)
from vulnhunter.source_hunt.benchmark_v2 import (
    BenchmarkCorpusKind,
    SourceBenchmarkCorpus,
    SourceGroundTruthCase,
)


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("controlled-corpus timestamps must include a timezone")
    return value.astimezone(UTC)


def _utc_json(value: datetime) -> str:
    """Return the same UTC representation emitted by Pydantic JSON mode."""
    return _utc(value).isoformat().replace("+00:00", "Z")


def _relative_path(value: str) -> str:
    normalized = PurePosixPath(value)
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError("controlled-corpus paths must be repository-relative")
    return normalized.as_posix()


def _identity_is_active(identity: ReviewerIdentity) -> None:
    if identity.status != "active":
        raise ValueError(f"governance identity {identity.reviewer_id} is not active")


class CorpusReviewVerdict(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ControlledGroundTruthSpec(BaseModel):
    """Human-authored case specification resolved against exact fixture source."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    vulnerability_class: str = Field(min_length=2, max_length=80)
    path: str = Field(min_length=1, max_length=512)
    anchor: str = Field(min_length=3, max_length=1_000)
    expected_vulnerable: bool

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _relative_path(value)


class ControlledFixtureFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    line_count: int = Field(ge=1)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _relative_path(value)


class ControlledGroundTruthCase(BaseModel):
    """Ground truth bound to the exact source bytes containing the reviewed line."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    vulnerability_class: str = Field(min_length=2, max_length=80)
    path: str = Field(min_length=1, max_length=512)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    expected_vulnerable: bool

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _relative_path(value)

    @model_validator(mode="after")
    def validate_lines(self) -> ControlledGroundTruthCase:
        if self.line_end < self.line_start:
            raise ValueError("controlled-corpus line range is invalid")
        return self


class CorpusReviewerBinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    reviewer_id: str = Field(min_length=2, max_length=64)
    identity_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ControlledCorpusDraft(BaseModel):
    """Tamper-evident corpus draft awaiting two assigned independent reviewers."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    draft_id: str = Field(pattern=r"^source-corpus-draft-[0-9a-f]{24}$")
    corpus_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    repository_id: str = Field(min_length=2, max_length=128)
    source_revision: str = Field(min_length=1, max_length=256)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: tuple[ControlledFixtureFile, ...]
    cases: tuple[ControlledGroundTruthCase, ...]
    prepared_by: str = Field(min_length=2, max_length=64)
    preparer_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assigned_reviewers: tuple[CorpusReviewerBinding, CorpusReviewerBinding]
    created_at: datetime
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def verify_integrity(self) -> ControlledCorpusDraft:
        canonical = self.model_dump(mode="json", exclude={"draft_id", "draft_sha256"})
        digest = _canonical_sha256(canonical)
        if digest != self.draft_sha256:
            raise ValueError("controlled-corpus draft digest does not match its contents")
        if self.draft_id != f"source-corpus-draft-{digest[:24]}":
            raise ValueError("controlled-corpus draft identifier does not match its digest")
        if not self.files or not self.cases:
            raise ValueError("controlled-corpus draft requires fixture files and cases")
        case_ids = [item.case_id for item in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("controlled-corpus case identifiers must be unique")
        reviewer_ids = [item.reviewer_id for item in self.assigned_reviewers]
        if len(set(reviewer_ids)) != 2:
            raise ValueError("controlled-corpus draft requires two distinct reviewers")
        if self.prepared_by in reviewer_ids:
            raise ValueError("corpus preparer cannot be an assigned reviewer")
        file_map = {item.path: item for item in self.files}
        if len(file_map) != len(self.files):
            raise ValueError("controlled-corpus fixture file paths must be unique")
        for case in self.cases:
            source = file_map.get(case.path)
            if source is None:
                raise ValueError("controlled-corpus case references a missing fixture file")
            if source.sha256 != case.source_sha256:
                raise ValueError("controlled-corpus case source digest does not match fixture file")
            if case.line_end > source.line_count:
                raise ValueError("controlled-corpus case line range exceeds fixture source")
        if not any(item.expected_vulnerable for item in self.cases):
            raise ValueError("controlled corpus must include at least one vulnerable case")
        if not any(not item.expected_vulnerable for item in self.cases):
            raise ValueError("controlled corpus must include at least one non-vulnerable case")
        return self


class CorpusReviewAttestation(BaseModel):
    """One identity-bound review of an exact controlled-corpus draft."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    attestation_id: str = Field(pattern=r"^source-corpus-review-[0-9a-f]{24}$")
    draft_id: str
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_id: str = Field(min_length=2, max_length=64)
    reviewer_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verdict: CorpusReviewVerdict
    reason: str = Field(min_length=8, max_length=2_000)
    reviewed_at: datetime
    attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        draft: ControlledCorpusDraft,
        reviewer: ReviewerIdentity,
        verdict: CorpusReviewVerdict,
        reason: str,
        reviewed_at: datetime | None = None,
    ) -> CorpusReviewAttestation:
        _identity_is_active(reviewer)
        if "reviewer" not in reviewer.roles:
            raise ValueError("controlled-corpus review requires the reviewer role")
        bindings = {item.reviewer_id: item for item in draft.assigned_reviewers}
        binding = bindings.get(reviewer.reviewer_id)
        if binding is None:
            raise ValueError("reviewer is not assigned to this controlled-corpus draft")
        if binding.identity_record_sha256 != reviewer.record_sha256:
            raise ValueError("reviewer identity record changed after corpus assignment")
        if reviewer.reviewer_id == draft.prepared_by:
            raise ValueError("corpus preparer cannot review their own draft")
        canonical = {
            "draft_id": draft.draft_id,
            "draft_sha256": draft.draft_sha256,
            "reviewer_id": reviewer.reviewer_id,
            "reviewer_identity_sha256": reviewer.record_sha256,
            "verdict": verdict.value,
            "reason": reason.strip(),
            "reviewed_at": _utc_json(reviewed_at or datetime.now(UTC)),
        }
        digest = _canonical_sha256(canonical)
        return cls(
            attestation_id=f"source-corpus-review-{digest[:24]}",
            attestation_sha256=digest,
            **canonical,
        )

    @field_validator("reviewed_at")
    @classmethod
    def validate_reviewed_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def verify_integrity(self) -> CorpusReviewAttestation:
        canonical = self.model_dump(
            mode="json",
            exclude={"attestation_id", "attestation_sha256"},
        )
        digest = _canonical_sha256(canonical)
        if digest != self.attestation_sha256:
            raise ValueError("controlled-corpus review digest does not match its contents")
        if self.attestation_id != f"source-corpus-review-{digest[:24]}":
            raise ValueError("controlled-corpus review identifier does not match its digest")
        return self


class CorpusReviewLedger:
    """Append-only local ledger: one immutable decision per reviewer and draft."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    @staticmethod
    def _reviewer_key(reviewer_id: str) -> str:
        return hashlib.sha256(reviewer_id.encode("utf-8")).hexdigest()[:24]

    def _path(self, draft_id: str, reviewer_id: str) -> Path:
        return self.root / draft_id / f"{self._reviewer_key(reviewer_id)}.json"

    def record(self, attestation: CorpusReviewAttestation) -> Path:
        destination = self._path(attestation.draft_id, attestation.reviewer_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            attestation.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
        ) + "\n"
        try:
            with destination.open("x", encoding="utf-8") as handle:
                handle.write(payload)
        except FileExistsError as exc:
            existing = CorpusReviewAttestation.model_validate_json(
                destination.read_text(encoding="utf-8")
            )
            if existing == attestation:
                return destination
            raise ValueError(
                "controlled-corpus reviewer already recorded an immutable decision for this draft"
            ) from exc
        return destination

    def load_assigned(
        self,
        draft: ControlledCorpusDraft,
    ) -> tuple[CorpusReviewAttestation, CorpusReviewAttestation]:
        reviews: list[CorpusReviewAttestation] = []
        for binding in draft.assigned_reviewers:
            path = self._path(draft.draft_id, binding.reviewer_id)
            try:
                review = CorpusReviewAttestation.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except FileNotFoundError as exc:
                raise ValueError(
                    f"assigned reviewer {binding.reviewer_id} has not recorded a decision"
                ) from exc
            if review.reviewer_id != binding.reviewer_id:
                raise ValueError("controlled-corpus review ledger identity binding is invalid")
            if review.draft_sha256 != draft.draft_sha256:
                raise ValueError("controlled-corpus review ledger contains a stale draft decision")
            reviews.append(review)
        return (reviews[0], reviews[1])


class ControlledCorpusRelease(BaseModel):
    """Reviewed controlled-lab ground truth released for benchmark use."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    release_id: str = Field(pattern=r"^source-corpus-release-[0-9a-f]{24}$")
    draft: ControlledCorpusDraft
    reviews: tuple[CorpusReviewAttestation, CorpusReviewAttestation]
    corpus: SourceBenchmarkCorpus
    released_by: str = Field(min_length=2, max_length=64)
    releaser_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    released_at: datetime
    release_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @field_validator("released_at")
    @classmethod
    def validate_released_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def verify_integrity(self) -> ControlledCorpusRelease:
        canonical = self.model_dump(mode="json", exclude={"release_id", "release_sha256"})
        digest = _canonical_sha256(canonical)
        if digest != self.release_sha256:
            raise ValueError("controlled-corpus release digest does not match its contents")
        if self.release_id != f"source-corpus-release-{digest[:24]}":
            raise ValueError("controlled-corpus release identifier does not match its digest")
        if self.corpus.kind != BenchmarkCorpusKind.CONTROLLED_LAB:
            raise ValueError("controlled-corpus release must contain controlled-lab ground truth")
        if self.corpus.corpus_id != self.draft.corpus_id:
            raise ValueError("released corpus identifier does not match its reviewed draft")
        expected_cases = tuple(
            SourceGroundTruthCase(
                case_id=item.case_id,
                vulnerability_class=item.vulnerability_class,
                path=item.path,
                line_start=item.line_start,
                line_end=item.line_end,
                expected_vulnerable=item.expected_vulnerable,
            )
            for item in self.draft.cases
        )
        if self.corpus.cases != expected_cases:
            raise ValueError("released corpus cases do not match the reviewed draft")
        expected_ids = {item.reviewer_id for item in self.draft.assigned_reviewers}
        actual_ids = {item.reviewer_id for item in self.reviews}
        if actual_ids != expected_ids:
            raise ValueError("controlled-corpus release does not contain both assigned reviews")
        if any(item.verdict != CorpusReviewVerdict.APPROVED for item in self.reviews):
            raise ValueError("controlled-corpus release contains a non-approval review")
        return self


class ReviewedSourceBenchmarkSuite(BaseModel):
    """Benchmark suite assembled only from independently reviewed corpus releases."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    suite_release_id: str = Field(pattern=r"^source-suite-release-[0-9a-f]{24}$")
    suite: SourceBenchmarkSuite
    corpus_releases: tuple[ControlledCorpusRelease, ...]
    released_by: str = Field(min_length=2, max_length=64)
    releaser_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    released_at: datetime
    suite_release_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @field_validator("released_at")
    @classmethod
    def validate_released_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def verify_integrity(self) -> ReviewedSourceBenchmarkSuite:
        canonical = self.model_dump(
            mode="json",
            exclude={"suite_release_id", "suite_release_sha256"},
        )
        digest = _canonical_sha256(canonical)
        if digest != self.suite_release_sha256:
            raise ValueError("reviewed benchmark suite release digest does not match its contents")
        if self.suite_release_id != f"source-suite-release-{digest[:24]}":
            raise ValueError(
                "reviewed benchmark suite release identifier does not match its digest"
            )
        if not self.corpus_releases:
            raise ValueError("reviewed benchmark suite cannot be empty")
        corpus_ids = [item.corpus.corpus_id for item in self.corpus_releases]
        if len(corpus_ids) != len(set(corpus_ids)):
            raise ValueError("reviewed benchmark suite corpus identifiers must be unique")
        expected_entries = tuple(
            SourceBenchmarkSuiteEntry(
                corpus=item.corpus,
                repository_id=item.draft.repository_id,
                source_revision=item.draft.source_revision,
                snapshot_sha256=item.draft.snapshot_sha256,
            )
            for item in self.corpus_releases
        )
        if self.suite.entries != expected_entries:
            raise ValueError("reviewed benchmark suite does not match its corpus releases")
        if any(
            entry.corpus.kind != BenchmarkCorpusKind.CONTROLLED_LAB
            for entry in self.suite.entries
        ):
            raise ValueError("reviewed benchmark suite may contain only controlled-lab corpora")
        return self


class ControlledBenchmarkCampaignEvidence(BaseModel):
    """Self-contained acceptance evidence over an independently reviewed suite."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(pattern=r"^source-controlled-campaign-[0-9a-f]{24}$")
    suite_release: ReviewedSourceBenchmarkSuite
    policy: SourceBenchmarkAcceptancePolicy
    acceptance_bundle: SourceBenchmarkAcceptanceBundle
    run_by: str = Field(min_length=2, max_length=64)
    runner_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def verify_integrity(self) -> ControlledBenchmarkCampaignEvidence:
        canonical = self.model_dump(mode="json", exclude={"evidence_id", "evidence_sha256"})
        digest = _canonical_sha256(canonical)
        if digest != self.evidence_sha256:
            raise ValueError("controlled benchmark campaign evidence digest does not match")
        if self.evidence_id != f"source-controlled-campaign-{digest[:24]}":
            raise ValueError("controlled benchmark campaign evidence identifier is invalid")
        acceptance = self.acceptance_bundle.acceptance
        if acceptance.suite_sha256 != self.suite_release.suite.suite_sha256:
            raise ValueError("campaign evidence acceptance is bound to a different suite")
        if acceptance.policy_sha256 != self.policy.policy_sha256:
            raise ValueError("campaign evidence acceptance is bound to a different policy")
        return self
