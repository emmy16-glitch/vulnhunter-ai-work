from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from governance_test_support import REVIEWER_ONE_SECRET, make_governance_store, prepare_identities

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingConflict,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RemediationRecord,
    RemediationReviewChecklist,
    RemediationReviewError,
    RemediationReviewOutcome,
    RemediationReviewReceiptStore,
    RemediationReviewService,
    RemediationState,
    RemediationVerificationReference,
    RetestOutcome,
    RetestPlanRecord,
    RetestReceiptReference,
    VerificationState,
)

NOW = datetime(2026, 8, 1, 7, 0, tzinfo=UTC)


class _FixStore:
    def __init__(self, bundle):
        self.bundle = bundle

    def load(self, receipt_id: str):
        assert receipt_id == self.bundle.receipt_id
        return self.bundle


class _RetestStore:
    def __init__(self, bundle):
        self.bundle = bundle

    def load(self, receipt_id: str):
        assert receipt_id == self.bundle.receipt_id
        return self.bundle


def _evidence(evidence_id: str, character: str, provenance: str) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        sha256=character * 64,
        provenance=provenance,
        content_type="application/json",
    )


def _world(tmp_path: Path):
    finding_store = FindingStore(tmp_path / "findings.sqlite3")
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)

    original = _evidence(
        "evidence-original",
        "a",
        "independently reviewed original assessment evidence",
    )
    fix_reference = RemediationVerificationReference(
        receipt_id="fix-verification-" + "b" * 24,
        sha256="c" * 64,
        verdict="fixed",
        original_revision="1" * 40,
        fixed_revision="2" * 40,
        created_at=NOW - timedelta(minutes=20),
    )
    retest_plan = RetestPlanRecord.create(
        finding_id="finding-01",
        finding_revision=2,
        finding_fingerprint="d" * 64,
        remediation_id="remediation-" + "e" * 32,
        fix_verification_receipt_id=fix_reference.receipt_id,
        fixed_revision=fix_reference.fixed_revision,
        owner_id="retest-operator",
        check_references=("Run the exact cross-user ownership check.",),
        before_evidence_ids=(original.evidence_id,),
        created_at=NOW - timedelta(minutes=15),
        expires_at=NOW + timedelta(days=1),
    )
    retest_reference = RetestReceiptReference(
        receipt_id="retest-receipt-" + "f" * 24,
        retest_id=retest_plan.retest_id,
        sha256="1" * 64,
        outcome=RetestOutcome.PASSED,
        fixed_revision=fix_reference.fixed_revision,
        created_at=NOW - timedelta(minutes=10),
    )
    remediation = RemediationRecord(
        summary="Enforce object ownership before returning the selected user record.",
        owner_id="developer-owner",
        references=(original.evidence_id,),
        remediation_id=retest_plan.remediation_id,
        state=RemediationState.AWAITING_REVIEW,
        source_finding_revision=0,
        source_finding_fingerprint="d" * 64,
        plan_sha256="3" * 64,
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected.",
        verification_recipe="Run the exact cross-user check and regression suite.",
        verification_history=(fix_reference,),
        retest_history=(retest_reference,),
        created_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(days=7),
    )
    finding = Finding(
        finding_id="finding-01",
        campaign_id="campaign-01",
        fingerprint="d" * 64,
        title="IDOR",
        description="User lookup may expose another user's record without ownership checks.",
        severity=FindingSeverity.HIGH,
        confidence=90,
        verification=VerificationState.VERIFIED,
        status=FindingStatus.AWAITING_REMEDIATION_REVIEW,
        affected_asset="repo-01",
        affected_component="app/users.py",
        evidence=(
            original,
            _evidence(fix_reference.receipt_id, "c", "immutable fix verification"),
            _evidence(retest_reference.receipt_id, "1", "immutable passed retest"),
        ),
        remediation=remediation,
        retest_plans=(retest_plan,),
        retest_results=(retest_reference,),
        revision=4,
        created_at=NOW - timedelta(hours=2),
        updated_at=retest_reference.created_at,
    )
    finding_store.create(finding)

    fix_bundle = SimpleNamespace(
        receipt_id=fix_reference.receipt_id,
        builder_id="implementation-builder",
        verifier_id="read-only-fix-verifier",
        fixed_snapshot=SimpleNamespace(revision=fix_reference.fixed_revision),
        fingerprint=lambda: fix_reference.sha256,
    )
    retest_bundle = SimpleNamespace(
        receipt_id=retest_reference.receipt_id,
        outcome=RetestOutcome.PASSED,
        plan=SimpleNamespace(
            owner_id=retest_plan.owner_id,
            fixed_revision=retest_plan.fixed_revision,
        ),
        fingerprint=lambda: retest_reference.sha256,
    )
    receipt_store = RemediationReviewReceiptStore(
        tmp_path / "remediation-review-receipts",
        signing_key=b"test-remediation-review-signing-key",
    )
    service = RemediationReviewService(
        finding_store=finding_store,
        governance_store=governance_store,
        fix_verification_store=_FixStore(fix_bundle),
        retest_receipt_store=_RetestStore(retest_bundle),
        receipt_store=receipt_store,
        clock=lambda: NOW,
    )
    return finding_store, finding, service


def _approved_checklist() -> RemediationReviewChecklist:
    return RemediationReviewChecklist(
        evidence_lineage_complete=True,
        fixed_revision_matches=True,
        approved_scope_respected=True,
        security_claim_supported=True,
        regressions_acceptable=True,
    )


def test_approved_review_is_signed_and_advances_only_to_report_readiness(tmp_path):
    finding_store, finding, service = _world(tmp_path)

    updated, bundle = service.record(
        finding_id=finding.finding_id,
        expected_revision=finding.revision,
        reviewer_id="reviewer-a",
        reviewer_secret=REVIEWER_ONE_SECRET,
        checklist=_approved_checklist(),
        rationale="The passed retest and fixed revision support the remediation claim.",
        limitations=("Final report and merge approval remain separate.",),
    )

    assert bundle.outcome == RemediationReviewOutcome.APPROVED
    assert updated.status == FindingStatus.READY_FOR_REPORT
    assert updated.status not in {FindingStatus.REMEDIATED, FindingStatus.CLOSED}
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.REVIEW_APPROVED
    assert updated.remediation.review_history[-1].receipt_id == bundle.receipt_id
    assert updated.evidence[-1].sha256 == bundle.fingerprint()
    assert service.receipt_store.load(bundle.receipt_id) == bundle
    assert finding_store.get(finding.finding_id) == updated


def test_negative_checklist_returns_to_bounded_rework(tmp_path):
    _store, finding, service = _world(tmp_path)
    checklist = _approved_checklist().model_copy(update={"approved_scope_respected": False})

    updated, bundle = service.record(
        finding_id=finding.finding_id,
        expected_revision=finding.revision,
        reviewer_id="reviewer-a",
        reviewer_secret=REVIEWER_ONE_SECRET,
        checklist=checklist,
        rationale="The changed files exceed the exact remediation boundary.",
    )

    assert bundle.outcome == RemediationReviewOutcome.CHANGES_REQUESTED
    assert updated.status == FindingStatus.IN_REMEDIATION
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.REVIEW_NEEDS_REWORK


def test_unknown_checklist_abstains_and_blocks_report(tmp_path):
    _store, finding, service = _world(tmp_path)
    checklist = _approved_checklist().model_copy(update={"regressions_acceptable": None})

    updated, bundle = service.record(
        finding_id=finding.finding_id,
        expected_revision=finding.revision,
        reviewer_id="reviewer-a",
        reviewer_secret=REVIEWER_ONE_SECRET,
        checklist=checklist,
        rationale="The supplied evidence does not establish broader regression safety.",
    )

    assert bundle.outcome == RemediationReviewOutcome.CANNOT_VERIFY
    assert updated.status == FindingStatus.IN_REMEDIATION
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.REVIEW_NEEDS_REWORK


@pytest.mark.parametrize(
    "reviewer_id,secret,match",
    [
        ("developer-owner", REVIEWER_ONE_SECRET, "remediation owner"),
        ("implementation-builder", REVIEWER_ONE_SECRET, "implementation builder"),
        ("retest-operator", REVIEWER_ONE_SECRET, "retest operator"),
        ("read-only-fix-verifier", REVIEWER_ONE_SECRET, "fix verifier"),
    ],
)
def test_review_rejects_non_independent_actor(
    tmp_path,
    reviewer_id,
    secret,
    match,
):
    _store, finding, service = _world(tmp_path)

    with pytest.raises(RemediationReviewError, match=match):
        service.record(
            finding_id=finding.finding_id,
            expected_revision=finding.revision,
            reviewer_id=reviewer_id,
            reviewer_secret=secret,
            checklist=_approved_checklist(),
            rationale="This actor must not review its own work.",
        )

    assert tuple(service.receipt_store.root.glob("*.json")) == ()


def test_wrong_governance_secret_fails_before_receipt_persistence(tmp_path):
    _store, finding, service = _world(tmp_path)

    with pytest.raises(RemediationReviewError, match="authentication"):
        service.record(
            finding_id=finding.finding_id,
            expected_revision=finding.revision,
            reviewer_id="reviewer-a",
            reviewer_secret="wrong-secret",
            checklist=_approved_checklist(),
            rationale="This must not be accepted.",
        )

    assert tuple(service.receipt_store.root.glob("*.json")) == ()


def test_stale_writer_rolls_back_new_signed_receipt(tmp_path):
    _store, finding, service = _world(tmp_path)

    with pytest.raises(FindingConflict):
        service.record(
            finding_id=finding.finding_id,
            expected_revision=finding.revision - 1,
            reviewer_id="reviewer-a",
            reviewer_secret=REVIEWER_ONE_SECRET,
            checklist=_approved_checklist(),
            rationale="The stale writer must lose without orphaning a receipt.",
        )

    assert tuple(service.receipt_store.root.glob("*.json")) == ()


def test_tampered_signed_receipt_is_rejected(tmp_path):
    _store, finding, service = _world(tmp_path)
    _updated, bundle = service.record(
        finding_id=finding.finding_id,
        expected_revision=finding.revision,
        reviewer_id="reviewer-a",
        reviewer_secret=REVIEWER_ONE_SECRET,
        checklist=_approved_checklist(),
        rationale="The evidence supports independent review approval.",
    )
    path = service.receipt_store.root / f"{bundle.receipt_id}.json"
    path.write_text(path.read_text(encoding="utf-8").replace("approved", "blocked", 1))

    with pytest.raises(RemediationReviewError, match="signature|integrity"):
        service.receipt_store.load(bundle.receipt_id)
