"""Services for governed controlled Source Hunt corpus preparation and campaigns."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.governance.models import ReviewerIdentity
from vulnhunter.source_hunt.benchmark_acceptance import (
    SourceBenchmarkAcceptanceBundle,
    SourceBenchmarkAcceptanceEvaluator,
    SourceBenchmarkAcceptancePolicy,
    SourceBenchmarkCampaignRunner,
    SourceBenchmarkSuite,
    SourceBenchmarkSuiteEntry,
)
from vulnhunter.source_hunt.benchmark_v2 import (
    BenchmarkCorpusKind,
    SourceBenchmarkCorpus,
    SourceGroundTruthCase,
)
from vulnhunter.source_hunt.controlled_corpus_models import (
    ControlledBenchmarkCampaignEvidence,
    ControlledCorpusDraft,
    ControlledCorpusRelease,
    ControlledFixtureFile,
    ControlledGroundTruthCase,
    ControlledGroundTruthSpec,
    CorpusReviewAttestation,
    CorpusReviewerBinding,
    CorpusReviewVerdict,
    ReviewedSourceBenchmarkSuite,
    _canonical_sha256,
    _identity_is_active,
    _utc_json,
)
from vulnhunter.source_hunt.models import RepositorySnapshot, SourceHuntReport


class ControlledCorpusDraftBuilder:
    """Resolve human-authored anchors against exact local fixture source without execution."""

    def build(
        self,
        *,
        corpus_id: str,
        snapshot: RepositorySnapshot,
        specs: tuple[ControlledGroundTruthSpec, ...],
        prepared_by: ReviewerIdentity,
        assigned_reviewers: tuple[ReviewerIdentity, ReviewerIdentity],
        created_at: datetime | None = None,
    ) -> ControlledCorpusDraft:
        _identity_is_active(prepared_by)
        if not {"campaign_admin", "reviewer"}.intersection(prepared_by.roles):
            raise ValueError("corpus preparation requires a reviewer or campaign administrator")
        if not specs:
            raise ValueError("controlled-corpus specification cannot be empty")

        reviewer_ids = [item.reviewer_id for item in assigned_reviewers]
        if len(set(reviewer_ids)) != 2:
            raise ValueError("controlled-corpus preparation requires two distinct reviewers")
        if prepared_by.reviewer_id in reviewer_ids:
            raise ValueError("corpus preparer cannot be an assigned reviewer")
        for reviewer in assigned_reviewers:
            _identity_is_active(reviewer)
            if "reviewer" not in reviewer.roles:
                raise ValueError("assigned controlled-corpus identities must hold reviewer role")

        root = Path(snapshot.repository_root).expanduser().resolve(strict=True)
        files: list[ControlledFixtureFile] = []
        source_lines: dict[str, tuple[str, ...]] = {}
        source_hashes: dict[str, str] = {}
        for item in snapshot.files:
            if item.language != "python":
                raise ValueError(
                    "current controlled Source Hunt corpus supports Python fixtures only"
                )
            path = (root / item.path).resolve(strict=True)
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise ValueError("fixture source escaped the controlled repository root") from exc
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if digest != item.sha256:
                raise ValueError("fixture source changed after repository snapshot")
            lines = tuple(raw.decode("utf-8").splitlines())
            if len(lines) != item.line_count:
                raise ValueError("fixture source line count changed after repository snapshot")
            files.append(
                ControlledFixtureFile(
                    path=item.path,
                    sha256=item.sha256,
                    line_count=item.line_count,
                )
            )
            source_lines[item.path] = lines
            source_hashes[item.path] = item.sha256

        cases: list[ControlledGroundTruthCase] = []
        for spec in specs:
            lines = source_lines.get(spec.path)
            if lines is None:
                raise ValueError(f"controlled-corpus case {spec.case_id} references unknown source")
            anchor = spec.anchor.strip()
            matches = [
                index
                for index, line in enumerate(lines, start=1)
                if line.strip() == anchor
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"controlled-corpus anchor for {spec.case_id} must match exactly one line"
                )
            line = matches[0]
            cases.append(
                ControlledGroundTruthCase(
                    case_id=spec.case_id,
                    vulnerability_class=spec.vulnerability_class,
                    path=spec.path,
                    source_sha256=source_hashes[spec.path],
                    line_start=line,
                    line_end=line,
                    expected_vulnerable=spec.expected_vulnerable,
                )
            )

        bindings = tuple(
            CorpusReviewerBinding(
                reviewer_id=reviewer.reviewer_id,
                identity_record_sha256=reviewer.record_sha256,
            )
            for reviewer in assigned_reviewers
        )
        canonical = {
            "corpus_id": corpus_id,
            "repository_id": snapshot.repository_id,
            "source_revision": snapshot.revision,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "files": [item.model_dump(mode="json") for item in files],
            "cases": [item.model_dump(mode="json") for item in cases],
            "prepared_by": prepared_by.reviewer_id,
            "preparer_identity_sha256": prepared_by.record_sha256,
            "assigned_reviewers": [item.model_dump(mode="json") for item in bindings],
            "created_at": _utc_json(created_at or datetime.now(UTC)),
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        return ControlledCorpusDraft(
            draft_id=f"source-corpus-draft-{digest[:24]}",
            draft_sha256=digest,
            **canonical,
        )


class ControlledCorpusReleaseService:
    """Release a draft only after both exact assigned reviewers approved it."""

    def release(
        self,
        *,
        draft: ControlledCorpusDraft,
        reviews: tuple[CorpusReviewAttestation, CorpusReviewAttestation],
        reviewer_identities: dict[str, ReviewerIdentity],
        released_by: ReviewerIdentity,
        released_at: datetime | None = None,
    ) -> ControlledCorpusRelease:
        _identity_is_active(released_by)
        if "campaign_admin" not in released_by.roles:
            raise ValueError("controlled-corpus release requires campaign administrator role")
        assigned_ids = {item.reviewer_id for item in draft.assigned_reviewers}
        review_ids = {item.reviewer_id for item in reviews}
        if review_ids != assigned_ids:
            raise ValueError(
                "controlled-corpus release requires both assigned reviewer attestations"
            )
        if released_by.reviewer_id in assigned_ids or released_by.reviewer_id == draft.prepared_by:
            raise ValueError("corpus releaser must be independent from preparer and reviewers")
        bindings = {item.reviewer_id: item for item in draft.assigned_reviewers}
        for review in reviews:
            if review.draft_id != draft.draft_id or review.draft_sha256 != draft.draft_sha256:
                raise ValueError("controlled-corpus review is bound to a different draft")
            if review.verdict != CorpusReviewVerdict.APPROVED:
                raise ValueError("controlled-corpus release requires two approvals")
            identity = reviewer_identities.get(review.reviewer_id)
            if identity is None:
                raise ValueError("controlled-corpus reviewer identity is unavailable")
            _identity_is_active(identity)
            if "reviewer" not in identity.roles:
                raise ValueError("controlled-corpus reviewer no longer holds reviewer role")
            if identity.record_sha256 != review.reviewer_identity_sha256:
                raise ValueError("controlled-corpus reviewer identity changed after attestation")
            if identity.record_sha256 != bindings[review.reviewer_id].identity_record_sha256:
                raise ValueError("controlled-corpus reviewer identity changed after assignment")

        corpus = SourceBenchmarkCorpus.create(
            corpus_id=draft.corpus_id,
            kind=BenchmarkCorpusKind.CONTROLLED_LAB,
            cases=tuple(
                SourceGroundTruthCase(
                    case_id=item.case_id,
                    vulnerability_class=item.vulnerability_class,
                    path=item.path,
                    line_start=item.line_start,
                    line_end=item.line_end,
                    expected_vulnerable=item.expected_vulnerable,
                )
                for item in draft.cases
            ),
        )
        canonical = {
            "draft": draft.model_dump(mode="json"),
            "reviews": [item.model_dump(mode="json") for item in reviews],
            "corpus": corpus.model_dump(mode="json"),
            "released_by": released_by.reviewer_id,
            "releaser_identity_sha256": released_by.record_sha256,
            "released_at": _utc_json(released_at or datetime.now(UTC)),
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        return ControlledCorpusRelease(
            release_id=f"source-corpus-release-{digest[:24]}",
            release_sha256=digest,
            **canonical,
        )


class ReviewedSourceBenchmarkSuiteBuilder:
    """Build a benchmark suite only from released controlled-lab corpora."""

    def build(
        self,
        *,
        suite_id: str,
        releases: tuple[ControlledCorpusRelease, ...],
        released_by: ReviewerIdentity,
        released_at: datetime | None = None,
    ) -> ReviewedSourceBenchmarkSuite:
        _identity_is_active(released_by)
        if "campaign_admin" not in released_by.roles:
            raise ValueError("benchmark suite release requires campaign administrator role")
        if not releases:
            raise ValueError("reviewed benchmark suite requires at least one corpus release")
        corpus_ids = [item.corpus.corpus_id for item in releases]
        if len(corpus_ids) != len(set(corpus_ids)):
            raise ValueError("reviewed benchmark suite corpus identifiers must be unique")
        entries = tuple(
            SourceBenchmarkSuiteEntry(
                corpus=item.corpus,
                repository_id=item.draft.repository_id,
                source_revision=item.draft.source_revision,
                snapshot_sha256=item.draft.snapshot_sha256,
            )
            for item in releases
        )
        suite = SourceBenchmarkSuite.create(suite_id=suite_id, entries=entries)
        canonical = {
            "suite": suite.model_dump(mode="json"),
            "corpus_releases": [item.model_dump(mode="json") for item in releases],
            "released_by": released_by.reviewer_id,
            "releaser_identity_sha256": released_by.record_sha256,
            "released_at": _utc_json(released_at or datetime.now(UTC)),
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        return ReviewedSourceBenchmarkSuite(
            suite_release_id=f"source-suite-release-{digest[:24]}",
            suite_release_sha256=digest,
            **canonical,
        )


class ControlledBenchmarkCampaignRunner:
    """Evaluate pre-produced reports over a reviewed suite; never scans or calls a model."""

    def run(
        self,
        *,
        suite_release: ReviewedSourceBenchmarkSuite,
        policy: SourceBenchmarkAcceptancePolicy,
        baseline_engine_revision: str,
        candidate_engine_revision: str,
        baseline_reports: dict[str, SourceHuntReport],
        candidate_reports: dict[str, SourceHuntReport],
        run_by: ReviewerIdentity,
        created_at: datetime | None = None,
    ) -> ControlledBenchmarkCampaignEvidence:
        _identity_is_active(run_by)
        if "campaign_admin" not in run_by.roles:
            raise ValueError("controlled benchmark campaign requires campaign administrator role")
        runner = SourceBenchmarkCampaignRunner()
        baseline = runner.run(
            label="baseline",
            engine_revision=baseline_engine_revision,
            suite=suite_release.suite,
            reports=baseline_reports,
        )
        candidate = runner.run(
            label="candidate",
            engine_revision=candidate_engine_revision,
            suite=suite_release.suite,
            reports=candidate_reports,
        )
        acceptance = SourceBenchmarkAcceptanceEvaluator().evaluate(
            policy=policy,
            baseline=baseline,
            candidate=candidate,
        )
        bundle = SourceBenchmarkAcceptanceBundle.create(
            baseline=baseline,
            candidate=candidate,
            acceptance=acceptance,
        )
        canonical = {
            "suite_release": suite_release.model_dump(mode="json"),
            "policy": policy.model_dump(mode="json"),
            "acceptance_bundle": bundle.model_dump(mode="json"),
            "run_by": run_by.reviewer_id,
            "runner_identity_sha256": run_by.record_sha256,
            "created_at": _utc_json(created_at or datetime.now(UTC)),
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        return ControlledBenchmarkCampaignEvidence(
            evidence_id=f"source-controlled-campaign-{digest[:24]}",
            evidence_sha256=digest,
            **canonical,
        )
