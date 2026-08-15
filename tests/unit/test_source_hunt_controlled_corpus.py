from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from django.core.management import call_command
from pydantic import TypeAdapter, ValidationError

from vulnhunter.governance.models import ReviewerIdentity
from vulnhunter.governance.service import bootstrap_administrator, create_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.source_hunt.benchmark_acceptance import (
    BenchmarkAcceptanceVerdict,
    SourceBenchmarkAcceptancePolicy,
)
from vulnhunter.source_hunt.controlled_corpus import (
    ControlledBenchmarkCampaignEvidence,
    ControlledBenchmarkCampaignRunner,
    ControlledCorpusDraft,
    ControlledCorpusDraftBuilder,
    ControlledCorpusReleaseService,
    ControlledGroundTruthSpec,
    CorpusReviewAttestation,
    CorpusReviewLedger,
    CorpusReviewVerdict,
    ReviewedSourceBenchmarkSuiteBuilder,
)
from vulnhunter.source_hunt.models import (
    CandidateDisposition,
    CapabilityAssessment,
    FalsificationDecision,
    GroqHypothesis,
    SourceCandidate,
    SourceHuntReport,
    SourceHuntStage,
    SourceReference,
)
from vulnhunter.source_hunt.service import RepositorySnapshotBuilder, SourceHuntPolicy

_NOW = datetime(2026, 8, 15, 10, 0, tzinfo=UTC)
_FIXTURE = Path(__file__).parents[1] / "fixtures" / "source_hunt_controlled" / "python_core"


def _identity(reviewer_id: str, roles: tuple[str, ...], marker: str) -> ReviewerIdentity:
    return ReviewerIdentity(
        reviewer_id=reviewer_id,
        display_name=reviewer_id,
        roles=roles,
        conflict_tags=(),
        status="active",
        credential_salt="a" * 24,
        credential_hash="b" * 48,
        created_by="root-admin",
        created_at=_NOW,
        status_changed_at=None,
        status_reason=None,
        record_sha256=marker * 64,
    )


def _specs() -> tuple[ControlledGroundTruthSpec, ...]:
    return TypeAdapter(tuple[ControlledGroundTruthSpec, ...]).validate_json(
        (_FIXTURE / "cases.json").read_text(encoding="utf-8")
    )


def _snapshot(root: Path = _FIXTURE):
    return RepositorySnapshotBuilder(SourceHuntPolicy(approved_roots=(root.parent,))).build(
        root,
        revision="c" * 40,
    )


def _draft(root: Path = _FIXTURE) -> ControlledCorpusDraft:
    return ControlledCorpusDraftBuilder().build(
        corpus_id="python-core-v1",
        snapshot=_snapshot(root),
        specs=_specs(),
        prepared_by=_identity("preparer", ("reviewer",), "1"),
        assigned_reviewers=(
            _identity("reviewer-a", ("reviewer",), "2"),
            _identity("reviewer-b", ("reviewer",), "3"),
        ),
        created_at=_NOW,
    )


def _released():
    draft = _draft()
    reviewer_a = _identity("reviewer-a", ("reviewer",), "2")
    reviewer_b = _identity("reviewer-b", ("reviewer",), "3")
    reviews = (
        CorpusReviewAttestation.create(
            draft=draft,
            reviewer=reviewer_a,
            verdict=CorpusReviewVerdict.APPROVED,
            reason="Reviewed exact vulnerable and guarded source anchors.",
            reviewed_at=_NOW,
        ),
        CorpusReviewAttestation.create(
            draft=draft,
            reviewer=reviewer_b,
            verdict=CorpusReviewVerdict.APPROVED,
            reason="Independently verified labels and exact source bindings.",
            reviewed_at=_NOW,
        ),
    )
    release = ControlledCorpusReleaseService().release(
        draft=draft,
        reviews=reviews,
        reviewer_identities={
            reviewer_a.reviewer_id: reviewer_a,
            reviewer_b.reviewer_id: reviewer_b,
        },
        released_by=_identity("release-admin", ("campaign_admin",), "4"),
        released_at=_NOW,
    )
    return draft, reviews, release


def _candidate(case, candidate_id: str) -> SourceCandidate:
    reference = SourceReference(
        path=case.path,
        source_sha256=case.source_sha256,
        line_start=case.line_start,
        line_end=case.line_end,
        symbol="controlled_fixture",
    )
    return SourceCandidate(
        candidate_id=candidate_id,
        hypothesis=GroqHypothesis(
            title=f"{case.vulnerability_class} candidate",
            vulnerability_class=case.vulnerability_class,
            summary="Controlled benchmark candidate.",
            entry_point=reference,
            sink=reference,
            path=(reference,),
            evidence_refs=(reference,),
            confidence=90,
        ),
        falsification=FalsificationDecision(
            disposition=CandidateDisposition.SURVIVED,
            reason="Controlled benchmark survived falsification.",
        ),
        capability=CapabilityAssessment(
            meaningful=True,
            required_attacker_capability="Reach the controlled fixture input.",
            resulting_capability="Reach the controlled sink.",
            impact_boundary="Controlled fixture only.",
            reason="Synthetic report used only for deterministic evaluator testing.",
        ),
    )


def _report(draft: ControlledCorpusDraft, detected_case_ids: set[str], report_id: str):
    cases = {item.case_id: item for item in draft.cases}
    candidates = tuple(
        _candidate(cases[case_id], f"candidate-{index}")
        for index, case_id in enumerate(sorted(detected_case_ids), start=1)
    )
    return SourceHuntReport(
        report_id=report_id,
        stage=SourceHuntStage.COMPLETE,
        snapshot=_snapshot(),
        approval_id="source-approval-controlled",
        model="controlled-test-model",
        surfaces_examined=len(draft.cases),
        model_calls=0,
        candidates=candidates,
        rejected_count=0,
        abstained_count=0,
        created_at=_NOW,
    )


def test_seed_fixture_resolves_to_exact_source_hashes_and_balanced_cases():
    draft = _draft()

    assert len(draft.cases) == 8
    assert sum(item.expected_vulnerable for item in draft.cases) == 4
    assert sum(not item.expected_vulnerable for item in draft.cases) == 4
    assert {item.path for item in draft.cases} == {"app.py"}
    assert {item.source_sha256 for item in draft.cases} == {draft.files[0].sha256}
    assert draft.production_accuracy_claim_permitted is False


def test_draft_builder_rejects_source_changed_after_snapshot(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    source = root / "app.py"
    source.write_text((_FIXTURE / "app.py").read_text(encoding="utf-8"), encoding="utf-8")
    snapshot = _snapshot(root)
    source.write_text(source.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")

    with pytest.raises(ValueError, match="changed after repository snapshot"):
        ControlledCorpusDraftBuilder().build(
            corpus_id="python-core-drift",
            snapshot=snapshot,
            specs=_specs(),
            prepared_by=_identity("preparer", ("reviewer",), "1"),
            assigned_reviewers=(
                _identity("reviewer-a", ("reviewer",), "2"),
                _identity("reviewer-b", ("reviewer",), "3"),
            ),
            created_at=_NOW,
        )


def test_release_requires_two_exact_independent_current_reviewer_approvals():
    draft, reviews, release = _released()

    assert release.corpus.corpus_id == draft.corpus_id
    assert len(release.corpus.cases) == len(draft.cases)
    assert release.production_accuracy_claim_permitted is False

    rejected = CorpusReviewAttestation.create(
        draft=draft,
        reviewer=_identity("reviewer-b", ("reviewer",), "3"),
        verdict=CorpusReviewVerdict.REJECTED,
        reason="One expected label needs correction before corpus release.",
        reviewed_at=_NOW,
    )
    with pytest.raises(ValueError, match="requires two approvals"):
        ControlledCorpusReleaseService().release(
            draft=draft,
            reviews=(reviews[0], rejected),
            reviewer_identities={
                "reviewer-a": _identity("reviewer-a", ("reviewer",), "2"),
                "reviewer-b": _identity("reviewer-b", ("reviewer",), "3"),
            },
            released_by=_identity("release-admin", ("campaign_admin",), "4"),
            released_at=_NOW,
        )


def test_review_ledger_is_append_only_and_rejection_cannot_be_replaced(tmp_path):
    draft = _draft()
    reviewer = _identity("reviewer-a", ("reviewer",), "2")
    ledger = CorpusReviewLedger(tmp_path / "ledger")
    rejected = CorpusReviewAttestation.create(
        draft=draft,
        reviewer=reviewer,
        verdict=CorpusReviewVerdict.REJECTED,
        reason="The path traversal label needs another source review.",
        reviewed_at=_NOW,
    )
    ledger.record(rejected)
    approved = CorpusReviewAttestation.create(
        draft=draft,
        reviewer=reviewer,
        verdict=CorpusReviewVerdict.APPROVED,
        reason="Attempted replacement approval must not overwrite the first decision.",
        reviewed_at=_NOW,
    )

    with pytest.raises(ValueError, match="already recorded an immutable decision"):
        ledger.record(approved)


def test_review_and_release_tampering_fail_closed():
    draft, reviews, release = _released()
    review_payload = reviews[0].model_dump(mode="json")
    review_payload["reason"] = "tampered review"
    with pytest.raises(ValidationError, match="digest"):
        CorpusReviewAttestation.model_validate(review_payload)

    release_payload = release.model_dump(mode="json")
    release_payload["corpus"]["cases"][0]["expected_vulnerable"] = False
    with pytest.raises(ValidationError):
        type(release).model_validate(release_payload)

    draft_payload = draft.model_dump(mode="json")
    draft_payload["cases"][0]["line_start"] += 1
    with pytest.raises(ValidationError, match="digest"):
        ControlledCorpusDraft.model_validate(draft_payload)


def test_reviewed_suite_and_campaign_evidence_accept_improved_candidate():
    draft, _reviews, release = _released()
    admin = _identity("suite-admin", ("campaign_admin",), "5")
    suite_release = ReviewedSourceBenchmarkSuiteBuilder().build(
        suite_id="python-controlled-v1",
        releases=(release,),
        released_by=admin,
        released_at=_NOW,
    )
    vulnerable = [item.case_id for item in draft.cases if item.expected_vulnerable]
    baseline_ids = set(vulnerable[:-1])
    candidate_ids = set(vulnerable)
    baseline = _report(draft, baseline_ids, "source-report-baseline-controlled")
    candidate = _report(draft, candidate_ids, "source-report-candidate-controlled")
    policy = SourceBenchmarkAcceptancePolicy.create(
        policy_id="python-controlled-strict",
        minimum_cases=8,
        minimum_controlled_lab_cases=8,
        minimum_precision=1.0,
        minimum_recall=1.0,
        minimum_f1=1.0,
        maximum_false_positives=0,
        maximum_false_negatives=0,
    )

    evidence = ControlledBenchmarkCampaignRunner().run(
        suite_release=suite_release,
        policy=policy,
        baseline_engine_revision="a" * 40,
        candidate_engine_revision="b" * 40,
        baseline_reports={draft.corpus_id: baseline},
        candidate_reports={draft.corpus_id: candidate},
        run_by=admin,
        created_at=_NOW,
    )

    assert evidence.acceptance_bundle.acceptance.verdict == BenchmarkAcceptanceVerdict.ACCEPTED
    assert evidence.acceptance_bundle.baseline.metrics.false_negatives == 1
    assert evidence.acceptance_bundle.candidate.metrics.false_negatives == 0
    assert evidence.acceptance_bundle.candidate.metrics.recall == 1.0
    assert evidence.production_accuracy_claim_permitted is False

    payload = evidence.model_dump(mode="json")
    payload["run_by"] = "tampered-admin"
    with pytest.raises(ValidationError, match="digest"):
        ControlledBenchmarkCampaignEvidence.model_validate(payload)


def _secret_file(path: Path, secret: str) -> Path:
    path.write_text(secret + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.mark.django_db
def test_management_command_prepare_review_release_and_suite(settings, tmp_path, monkeypatch):
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.sqlite3")
    monkeypatch.setenv("VULNHUNTER_SOURCE_HUNT_CORPUS_ROOTS", str(_FIXTURE.parent))
    monkeypatch.setenv(
        "VULNHUNTER_SOURCE_HUNT_CORPUS_LEDGER_ROOT",
        str(tmp_path / "corpus-review-ledger"),
    )
    store = GovernanceStore.from_path(Path(settings.VULNHUNTER_GOVERNANCE_DATABASE))
    store.initialize()
    bootstrap_administrator(
        store,
        reviewer_id="root-admin",
        display_name="Root Admin",
        secret="root-secret-123",
        now=_NOW,
    )
    for reviewer_id, roles, secret in (
        ("preparer", ("reviewer",), "prepare-secret-123"),
        ("reviewer-a", ("reviewer",), "review-a-secret-123"),
        ("reviewer-b", ("reviewer",), "review-b-secret-123"),
        ("release-admin", ("campaign_admin",), "release-secret-123"),
    ):
        create_identity(
            store,
            actor_id="root-admin",
            actor_secret="root-secret-123",
            reviewer_id=reviewer_id,
            display_name=reviewer_id,
            secret=secret,
            roles=roles,
            now=_NOW,
        )

    draft_path = tmp_path / "draft.json"
    call_command(
        "vh_source_hunt_corpus",
        "--prepare",
        "--actor",
        "preparer",
        "--secret-file",
        str(_secret_file(tmp_path / "preparer.secret", "prepare-secret-123")),
        "--output",
        str(draft_path),
        "--fixture-root",
        str(_FIXTURE),
        "--revision",
        "c" * 40,
        "--corpus-id",
        "python-core-v1",
        "--spec-file",
        str(_FIXTURE / "cases.json"),
        "--reviewer",
        "reviewer-a",
        "--reviewer",
        "reviewer-b",
        verbosity=0,
    )
    draft = ControlledCorpusDraft.model_validate_json(draft_path.read_text(encoding="utf-8"))
    assert draft.corpus_id == "python-core-v1"

    review_paths = []
    for reviewer_id, secret in (
        ("reviewer-a", "review-a-secret-123"),
        ("reviewer-b", "review-b-secret-123"),
    ):
        review_path = tmp_path / f"{reviewer_id}.json"
        call_command(
            "vh_source_hunt_corpus",
            "--review",
            str(draft_path),
            "--actor",
            reviewer_id,
            "--secret-file",
            str(_secret_file(tmp_path / f"{reviewer_id}.secret", secret)),
            "--decision",
            "approved",
            "--reason",
            "Independently checked exact fixture labels and guarded controls.",
            "--output",
            str(review_path),
            verbosity=0,
        )
        review_paths.append(review_path)

    release_path = tmp_path / "release.json"
    call_command(
        "vh_source_hunt_corpus",
        "--release-corpus",
        str(draft_path),
        "--actor",
        "release-admin",
        "--secret-file",
        str(_secret_file(tmp_path / "release.secret", "release-secret-123")),
        "--output",
        str(release_path),
        verbosity=0,
    )

    suite_path = tmp_path / "suite.json"
    call_command(
        "vh_source_hunt_corpus",
        "--release-suite",
        "--actor",
        "release-admin",
        "--secret-file",
        str(tmp_path / "release.secret"),
        "--suite-id",
        "python-controlled-v1",
        "--corpus-release-file",
        str(release_path),
        "--output",
        str(suite_path),
        verbosity=0,
    )
    payload = json.loads(suite_path.read_text(encoding="utf-8"))
    assert payload["suite"]["suite_id"] == "python-controlled-v1"
    assert payload["production_accuracy_claim_permitted"] is False
