from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from vulnhunter.governance.service import (
    bootstrap_administrator,
    change_identity_status,
    create_identity,
)
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.source_hunt.benchmark_acceptance import (
    BenchmarkAcceptanceVerdict,
    SourceBenchmarkAcceptancePolicy,
)
from vulnhunter.source_hunt.benchmark_v2 import (
    BenchmarkCorpusKind,
    SourceBenchmarkCorpus,
    SourceGroundTruthCase,
)
from vulnhunter.source_hunt.controlled_corpus import (
    ControlledBenchmarkCampaignEvidence,
    ControlledBenchmarkCampaignManifest,
    ControlledBenchmarkCampaignService,
    ControlledCorpusDraft,
    ControlledCorpusReviewDecision,
    ControlledCorpusService,
    ControlledCorpusStore,
)
from vulnhunter.source_hunt.models import (
    CandidateDisposition,
    CapabilityAssessment,
    FalsificationDecision,
    GroqHypothesis,
    RepositoryFile,
    RepositorySnapshot,
    SourceCandidate,
    SourceHuntReport,
    SourceHuntStage,
    SourceReference,
)

_NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
_ADMIN_SECRET = "admin-controlled-corpus-secret"
_CREATOR_SECRET = "creator-controlled-corpus-secret"
_REVIEWER_A_SECRET = "reviewer-a-controlled-corpus-secret"
_REVIEWER_B_SECRET = "reviewer-b-controlled-corpus-secret"


def _governance(tmp_path: Path) -> GovernanceStore:
    store = GovernanceStore(tmp_path / "governance.sqlite3")
    store.initialize()
    bootstrap_administrator(
        store,
        reviewer_id="corpus-admin",
        display_name="Corpus Admin",
        secret=_ADMIN_SECRET,
        now=_NOW,
    )
    for reviewer_id, display_name, secret in (
        ("corpus-creator", "Corpus Creator", _CREATOR_SECRET),
        ("reviewer-a", "Reviewer A", _REVIEWER_A_SECRET),
        ("reviewer-b", "Reviewer B", _REVIEWER_B_SECRET),
    ):
        create_identity(
            store,
            actor_id="corpus-admin",
            actor_secret=_ADMIN_SECRET,
            reviewer_id=reviewer_id,
            display_name=display_name,
            secret=secret,
            roles=("reviewer",),
            now=_NOW,
        )
    return store


def _snapshot() -> RepositorySnapshot:
    return RepositorySnapshot(
        repository_id="controlled-fixture",
        repository_root="/private/not-persisted-in-binding",
        revision="1" * 40,
        snapshot_sha256="a" * 64,
        files=(
            RepositoryFile(
                path="app.py",
                sha256="b" * 64,
                size_bytes=240,
                language="python",
                line_count=20,
            ),
        ),
        total_bytes=240,
        created_at=_NOW,
    )


def _corpus(*, kind: BenchmarkCorpusKind = BenchmarkCorpusKind.CONTROLLED_LAB):
    return SourceBenchmarkCorpus.create(
        corpus_id="controlled-path-boundary",
        kind=kind,
        cases=(
            SourceGroundTruthCase(
                case_id="VH-CONTROLLED-001",
                vulnerability_class="path_traversal",
                path="app.py",
                line_start=10,
                line_end=10,
                expected_vulnerable=True,
            ),
        ),
    )


def _candidate(candidate_id: str) -> SourceCandidate:
    reference = SourceReference(
        path="app.py",
        source_sha256="b" * 64,
        line_start=10,
        line_end=10,
        symbol="download",
    )
    return SourceCandidate(
        candidate_id=candidate_id,
        hypothesis=GroqHypothesis(
            title="Untrusted file path reaches open",
            vulnerability_class="path_traversal",
            summary="Controlled fixture path reaches the filesystem sink.",
            entry_point=reference,
            sink=reference,
            path=(reference,),
            evidence_refs=(reference,),
            confidence=90,
        ),
        falsification=FalsificationDecision(
            disposition=CandidateDisposition.SURVIVED,
            reason="The controlled fixture contains no proven path boundary.",
        ),
        capability=CapabilityAssessment(
            meaningful=True,
            required_attacker_capability="Supply the controlled route argument",
            resulting_capability="Select a file path",
            impact_boundary="Controlled fixture filesystem boundary",
            reason="The fixture deliberately models an unsafe path boundary.",
        ),
    )


def _report(*, candidate_id: str | None, report_id: str) -> SourceHuntReport:
    candidates = (_candidate(candidate_id),) if candidate_id else ()
    return SourceHuntReport(
        report_id=report_id,
        stage=SourceHuntStage.COMPLETE,
        snapshot=_snapshot(),
        approval_id="source-approval-controlled",
        model="controlled-model",
        surfaces_examined=1,
        model_calls=1,
        candidates=candidates,
        rejected_count=0,
        abstained_count=0,
        created_at=_NOW,
    )


def _policy() -> SourceBenchmarkAcceptancePolicy:
    return SourceBenchmarkAcceptancePolicy.create(
        policy_id="controlled-promotion-policy",
        minimum_cases=1,
        minimum_controlled_lab_cases=1,
        minimum_precision=1.0,
        minimum_recall=1.0,
        minimum_f1=1.0,
        maximum_false_positives=0,
        maximum_false_negatives=0,
    )


def _released(tmp_path: Path):
    governance = _governance(tmp_path)
    service = ControlledCorpusService(governance)
    draft = service.create_draft(
        snapshot=_snapshot(),
        corpus=_corpus(),
        creator_id="corpus-creator",
        creator_secret=_CREATOR_SECRET,
        now=_NOW,
    )
    review_a = service.attest(
        draft=draft,
        reviewer_id="reviewer-a",
        reviewer_secret=_REVIEWER_A_SECRET,
        decision=ControlledCorpusReviewDecision.APPROVE,
        now=_NOW,
    )
    review_b = service.attest(
        draft=draft,
        reviewer_id="reviewer-b",
        reviewer_secret=_REVIEWER_B_SECRET,
        decision=ControlledCorpusReviewDecision.APPROVE,
        now=_NOW,
    )
    release = service.release(
        draft=draft,
        attestations=(review_b, review_a),
        now=_NOW,
    )
    return governance, service, draft, review_a, review_b, release


def test_two_authenticated_independent_reviews_release_and_campaign_accept(tmp_path):
    _governance_store, _service, draft, review_a, review_b, release = _released(tmp_path)

    assert release.draft.draft_id == draft.draft_id
    assert release.approved_reviewer_ids == ("reviewer-a", "reviewer-b")
    assert tuple(item.reviewer_id for item in release.attestations) == (
        "reviewer-a",
        "reviewer-b",
    )
    assert release.production_accuracy_claim_permitted is False
    assert review_a.draft_sha256 == review_b.draft_sha256 == draft.draft_sha256

    manifest = ControlledBenchmarkCampaignManifest.create(
        releases=(release,),
        policy=_policy(),
        baseline_engine_revision="2" * 40,
        candidate_engine_revision="3" * 40,
    )
    evidence = ControlledBenchmarkCampaignService().evaluate(
        manifest=manifest,
        baseline_reports={
            "controlled-path-boundary": _report(
                candidate_id="baseline-candidate", report_id="source-report-baseline"
            )
        },
        candidate_reports={
            "controlled-path-boundary": _report(
                candidate_id="v2-candidate", report_id="source-report-candidate"
            )
        },
    )

    assert evidence.acceptance_bundle.acceptance.verdict == BenchmarkAcceptanceVerdict.ACCEPTED
    assert evidence.acceptance_bundle.candidate.metrics.recall == 1.0
    assert evidence.acceptance_bundle.candidate.controlled_lab_cases == 1
    assert evidence.acceptance_bundle.candidate.synthetic_cases == 0
    assert evidence.production_accuracy_claim_permitted is False


def test_creator_self_review_duplicate_review_and_rejection_fail_closed(tmp_path):
    governance = _governance(tmp_path)
    service = ControlledCorpusService(governance)
    draft = service.create_draft(
        snapshot=_snapshot(),
        corpus=_corpus(),
        creator_id="corpus-creator",
        creator_secret=_CREATOR_SECRET,
        now=_NOW,
    )
    with pytest.raises(ValueError, match="cannot review"):
        service.attest(
            draft=draft,
            reviewer_id="corpus-creator",
            reviewer_secret=_CREATOR_SECRET,
            decision=ControlledCorpusReviewDecision.APPROVE,
            now=_NOW,
        )

    review_a = service.attest(
        draft=draft,
        reviewer_id="reviewer-a",
        reviewer_secret=_REVIEWER_A_SECRET,
        decision=ControlledCorpusReviewDecision.APPROVE,
        now=_NOW,
    )
    with pytest.raises(ValueError, match="only once"):
        service.release(draft=draft, attestations=(review_a, review_a), now=_NOW)

    rejection = service.attest(
        draft=draft,
        reviewer_id="reviewer-b",
        reviewer_secret=_REVIEWER_B_SECRET,
        decision=ControlledCorpusReviewDecision.REJECT,
        now=_NOW,
    )
    with pytest.raises(ValueError, match="rejected"):
        service.release(draft=draft, attestations=(review_a, rejection), now=_NOW)


def test_reviewer_must_still_be_active_when_release_is_created(tmp_path):
    governance = _governance(tmp_path)
    service = ControlledCorpusService(governance)
    draft = service.create_draft(
        snapshot=_snapshot(),
        corpus=_corpus(),
        creator_id="corpus-creator",
        creator_secret=_CREATOR_SECRET,
        now=_NOW,
    )
    review_a = service.attest(
        draft=draft,
        reviewer_id="reviewer-a",
        reviewer_secret=_REVIEWER_A_SECRET,
        decision=ControlledCorpusReviewDecision.APPROVE,
        now=_NOW,
    )
    review_b = service.attest(
        draft=draft,
        reviewer_id="reviewer-b",
        reviewer_secret=_REVIEWER_B_SECRET,
        decision=ControlledCorpusReviewDecision.APPROVE,
        now=_NOW,
    )
    change_identity_status(
        governance,
        actor_id="corpus-admin",
        actor_secret=_ADMIN_SECRET,
        reviewer_id="reviewer-b",
        status="revoked",
        reason="controlled test revocation",
        now=_NOW,
    )

    with pytest.raises(ValueError, match="no longer eligible"):
        service.release(draft=draft, attestations=(review_a, review_b), now=_NOW)


def test_draft_rejects_synthetic_missing_and_out_of_range_ground_truth(tmp_path):
    governance = _governance(tmp_path)
    service = ControlledCorpusService(governance)
    with pytest.raises(ValueError, match="controlled-lab"):
        service.create_draft(
            snapshot=_snapshot(),
            corpus=_corpus(kind=BenchmarkCorpusKind.SYNTHETIC),
            creator_id="corpus-creator",
            creator_secret=_CREATOR_SECRET,
            now=_NOW,
        )

    missing = SourceBenchmarkCorpus.create(
        corpus_id="missing-file-case",
        kind=BenchmarkCorpusKind.CONTROLLED_LAB,
        cases=(
            SourceGroundTruthCase(
                case_id="VH-MISSING-001",
                vulnerability_class="path_traversal",
                path="missing.py",
                line_start=1,
                line_end=1,
                expected_vulnerable=True,
            ),
        ),
    )
    with pytest.raises(ValueError, match="missing fixture file"):
        service.create_draft(
            snapshot=_snapshot(),
            corpus=missing,
            creator_id="corpus-creator",
            creator_secret=_CREATOR_SECRET,
            now=_NOW,
        )

    out_of_range = SourceBenchmarkCorpus.create(
        corpus_id="line-range-case",
        kind=BenchmarkCorpusKind.CONTROLLED_LAB,
        cases=(
            SourceGroundTruthCase(
                case_id="VH-RANGE-001",
                vulnerability_class="path_traversal",
                path="app.py",
                line_start=21,
                line_end=21,
                expected_vulnerable=True,
            ),
        ),
    )
    with pytest.raises(ValueError, match="line count"):
        service.create_draft(
            snapshot=_snapshot(),
            corpus=out_of_range,
            creator_id="corpus-creator",
            creator_secret=_CREATOR_SECRET,
            now=_NOW,
        )


def test_tampering_of_draft_release_manifest_and_evidence_is_rejected(tmp_path):
    _governance_store, _service, draft, _review_a, _review_b, release = _released(tmp_path)

    draft_payload = draft.model_dump(mode="json")
    draft_payload["fixture"]["snapshot_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="draft digest"):
        ControlledCorpusDraft.model_validate(draft_payload)

    release_payload = release.model_dump(mode="json")
    release_payload["approved_reviewer_ids"] = ["reviewer-a", "reviewer-x"]
    with pytest.raises(ValueError):
        type(release).model_validate(release_payload)

    manifest = ControlledBenchmarkCampaignManifest.create(
        releases=(release,),
        policy=_policy(),
        baseline_engine_revision="2" * 40,
        candidate_engine_revision="3" * 40,
    )
    manifest_payload = manifest.model_dump(mode="json")
    manifest_payload["candidate_engine_revision"] = "4" * 40
    with pytest.raises(ValueError, match="manifest digest"):
        ControlledBenchmarkCampaignManifest.model_validate(manifest_payload)

    evidence = ControlledBenchmarkCampaignService().evaluate(
        manifest=manifest,
        baseline_reports={
            "controlled-path-boundary": _report(
                candidate_id="baseline-candidate", report_id="source-report-baseline"
            )
        },
        candidate_reports={
            "controlled-path-boundary": _report(
                candidate_id="v2-candidate", report_id="source-report-candidate"
            )
        },
    )
    evidence_payload = evidence.model_dump(mode="json")
    evidence_payload["manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="evidence digest"):
        ControlledBenchmarkCampaignEvidence.model_validate(evidence_payload)


def test_store_is_idempotent_and_refuses_different_evidence_at_same_path(tmp_path):
    _governance_store, _service, draft, _review_a, _review_b, release = _released(tmp_path)
    store = ControlledCorpusStore(tmp_path / "corpus-evidence")

    first = store.save_draft(draft)
    second = store.save_draft(draft)
    assert first == second
    release_path = store.save_release(release)
    assert release_path.exists()

    first.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="different data"):
        store.save_draft(draft)


def test_controlled_campaign_command_persists_rejection_evidence_before_nonzero_exit(tmp_path):
    _governance_store, _service, _draft, _review_a, _review_b, release = _released(tmp_path)
    release_file = tmp_path / "release.json"
    policy_file = tmp_path / "policy.json"
    baseline_dir = tmp_path / "baseline"
    candidate_dir = tmp_path / "candidate"
    output = tmp_path / "evidence.json"
    baseline_dir.mkdir()
    candidate_dir.mkdir()
    release_file.write_text(release.model_dump_json(indent=2), encoding="utf-8")
    policy_file.write_text(_policy().model_dump_json(indent=2), encoding="utf-8")
    (baseline_dir / "controlled-path-boundary.json").write_text(
        _report(
            candidate_id="baseline-candidate",
            report_id="source-report-baseline",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    (candidate_dir / "controlled-path-boundary.json").write_text(
        _report(candidate_id=None, report_id="source-report-candidate").model_dump_json(indent=2),
        encoding="utf-8",
    )

    with pytest.raises(CommandError, match="benchmark rejected"):
        call_command(
            "vh_check_source_hunt_controlled_campaign",
            release_file=[str(release_file)],
            policy_file=str(policy_file),
            baseline_report_dir=str(baseline_dir),
            candidate_report_dir=str(candidate_dir),
            baseline_engine_revision="2" * 40,
            candidate_engine_revision="3" * 40,
            output=str(output),
        )

    persisted = ControlledBenchmarkCampaignEvidence.model_validate_json(
        output.read_text(encoding="utf-8")
    )
    assert persisted.acceptance_bundle.acceptance.verdict == BenchmarkAcceptanceVerdict.REJECTED
    assert persisted.acceptance_bundle.candidate.metrics.false_negatives == 1
    assert persisted.production_accuracy_claim_permitted is False
