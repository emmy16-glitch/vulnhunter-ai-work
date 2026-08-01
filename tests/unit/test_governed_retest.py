from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingConflict,
    FindingLifecycleError,
    FindingService,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    GovernedRetestError,
    GovernedRetestService,
    RemediationState,
    RemediationVerificationReference,
    RetestOutcome,
    RetestReceiptStore,
    VerificationState,
)
from vulnhunter.source_hunt import VerifierReceipt

NOW = datetime(2026, 8, 1, 6, 30, tzinfo=UTC)


def _evidence(
    evidence_id: str,
    digest_character: str,
    provenance: str,
) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        sha256=digest_character * 64,
        provenance=provenance,
        content_type="application/json",
    )


def _receipt(name: str, *, passed: bool = True) -> VerifierReceipt:
    return VerifierReceipt(
        verifier_id=name,
        passed=passed,
        exit_code=0 if passed else 1,
        output_sha256=hashlib.sha256(f"{name}:{passed}".encode()).hexdigest(),
        duration_seconds=0.25,
        safe_summary="Deterministic bounded retest receipt.",
    )


def _ready_for_retest(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    original = _evidence(
        "evidence-original",
        "a",
        "independently reviewed evidence from the original authorised assessment",
    )
    finding = Finding(
        finding_id="finding-01",
        campaign_id="campaign-01",
        fingerprint=Finding.create_fingerprint(
            campaign_id="campaign-01",
            title="IDOR",
            affected_asset="repo-01",
            affected_component="app/users.py",
        ),
        title="IDOR",
        description="User lookup may expose another user's record without ownership checks.",
        severity=FindingSeverity.HIGH,
        confidence=90,
        verification=VerificationState.VERIFIED,
        affected_asset="repo-01",
        affected_component="app/users.py",
        evidence=(original,),
        created_at=NOW - timedelta(hours=2),
        updated_at=NOW - timedelta(hours=2),
    )
    store.create(finding)
    lifecycle = FindingService(store)
    planned = lifecycle.start_remediation(
        "finding-01",
        owner_id="developer-01",
        summary="Enforce object ownership before returning the selected user record.",
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected by the RED security test.",
        verification_recipe="Run the independent read-only security and regression receipts.",
        references=(original.evidence_id,),
        expires_at=NOW + timedelta(days=7),
        expected_revision=0,
        now=NOW,
    )
    verified_at = NOW + timedelta(minutes=5)
    fixed = lifecycle.record_fix_verification(
        "finding-01",
        verification=RemediationVerificationReference(
            receipt_id="fix-verification-" + "b" * 24,
            sha256="c" * 64,
            verdict="fixed",
            original_revision="1" * 40,
            fixed_revision="2" * 40,
            created_at=verified_at,
        ),
        expected_revision=planned.revision,
        now=verified_at,
    )
    service = GovernedRetestService(
        finding_store=store,
        receipt_store=RetestReceiptStore(tmp_path / "retest-receipts"),
        clock=lambda: NOW + timedelta(minutes=10),
    )
    return store, original, fixed, service


def test_governed_retest_start_binds_latest_fixed_receipt_and_original_evidence(tmp_path):
    store, original, fixed, service = _ready_for_retest(tmp_path)

    started = service.start(
        finding_id="finding-01",
        expected_revision=fixed.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )

    assert started.status == FindingStatus.RETESTING
    assert started.revision == fixed.revision + 1
    assert len(started.retest_plans) == 1
    plan = started.retest_plans[0]
    assert plan.source_finding_revision == fixed.revision
    assert plan.fix_verification_receipt_id == (
        fixed.remediation.verification_history[-1].receipt_id
    )
    assert plan.fixed_revision == "2" * 40
    assert plan.before_evidence_ids == (original.evidence_id,)
    assert plan.plan_sha256 and len(plan.plan_sha256) == 64
    assert store.get("finding-01") == started


def test_passed_retest_advances_only_to_independent_review_readiness(tmp_path):
    store, original, fixed, service = _ready_for_retest(tmp_path)
    started = service.start(
        finding_id="finding-01",
        expected_revision=fixed.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )
    after = _evidence(
        "evidence-retest-after",
        "d",
        "bounded after-fix retest evidence for the exact fixed revision",
    )

    updated, bundle = service.record(
        finding_id="finding-01",
        retest_id=started.retest_plans[-1].retest_id,
        expected_revision=started.revision,
        before_evidence=(original,),
        after_evidence=(after,),
        check_receipts=(_receipt("idor-security-retest"), _receipt("user-api-regression")),
        original_issue_blocked=True,
        regression_free=True,
    )

    assert bundle.outcome == RetestOutcome.PASSED
    assert updated.status == FindingStatus.AWAITING_REMEDIATION_REVIEW
    assert updated.status != FindingStatus.REMEDIATED
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.AWAITING_REVIEW
    assert updated.retest_results[-1].receipt_id == bundle.receipt_id
    assert updated.retest_results[-1].outcome == RetestOutcome.PASSED
    assert updated.evidence[-1].evidence_id == bundle.receipt_id
    assert updated.evidence[-1].sha256 == bundle.fingerprint()
    assert store.get("finding-01") == updated
    assert service.receipt_store.load(bundle.receipt_id) == bundle


def test_failed_retest_blocks_review_and_returns_truthful_rework_state(tmp_path):
    _store, original, fixed, service = _ready_for_retest(tmp_path)
    started = service.start(
        finding_id="finding-01",
        expected_revision=fixed.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )
    after = _evidence(
        "evidence-retest-after",
        "e",
        "bounded retest evidence showing the claim still reproduces",
    )

    updated, bundle = service.record(
        finding_id="finding-01",
        retest_id=started.retest_plans[-1].retest_id,
        expected_revision=started.revision,
        before_evidence=(original,),
        after_evidence=(after,),
        check_receipts=(_receipt("idor-security-retest", passed=False),),
        original_issue_blocked=False,
        regression_free=None,
    )

    assert bundle.outcome == RetestOutcome.FAILED
    assert updated.status == FindingStatus.IN_REMEDIATION
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.RETEST_NEEDS_REWORK
    assert updated.status != FindingStatus.AWAITING_REMEDIATION_REVIEW
    assert updated.status != FindingStatus.REMEDIATED


def test_missing_deterministic_receipts_abstains_instead_of_passing(tmp_path):
    _store, original, fixed, service = _ready_for_retest(tmp_path)
    started = service.start(
        finding_id="finding-01",
        expected_revision=fixed.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )

    updated, bundle = service.record(
        finding_id="finding-01",
        retest_id=started.retest_plans[-1].retest_id,
        expected_revision=started.revision,
        before_evidence=(original,),
        after_evidence=(),
        check_receipts=(),
        original_issue_blocked=None,
        regression_free=None,
    )

    assert bundle.outcome == RetestOutcome.CANNOT_VERIFY
    assert updated.status == FindingStatus.IN_REMEDIATION
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.RETEST_NEEDS_REWORK


def test_retest_cancellation_is_append_only_and_returns_to_ready_for_retest(tmp_path):
    _store, _original, fixed, service = _ready_for_retest(tmp_path)
    started = service.start(
        finding_id="finding-01",
        expected_revision=fixed.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )

    updated, bundle = service.cancel(
        finding_id="finding-01",
        retest_id=started.retest_plans[-1].retest_id,
        expected_revision=started.revision,
        reason="The authorised test identity became unavailable before evidence collection.",
    )

    assert bundle.outcome == RetestOutcome.CANCELLED
    assert updated.status == FindingStatus.READY_FOR_RETEST
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.READY_FOR_RETEST
    assert updated.retest_results[-1].outcome == RetestOutcome.CANCELLED


def test_stale_retest_writer_loses_without_orphan_receipt(tmp_path):
    _store, original, fixed, service = _ready_for_retest(tmp_path)
    started = service.start(
        finding_id="finding-01",
        expected_revision=fixed.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )

    with pytest.raises(FindingConflict):
        service.record(
            finding_id="finding-01",
            retest_id=started.retest_plans[-1].retest_id,
            expected_revision=started.revision - 1,
            before_evidence=(original,),
            after_evidence=(
                _evidence(
                    "evidence-retest-after",
                    "f",
                    "bounded after-fix retest evidence",
                ),
            ),
            check_receipts=(_receipt("idor-security-retest"),),
            original_issue_blocked=True,
            regression_free=True,
        )

    assert tuple(service.receipt_store.root.glob("*.json")) == ()


def test_tampered_before_evidence_is_rejected_before_persistence(tmp_path):
    _store, original, fixed, service = _ready_for_retest(tmp_path)
    started = service.start(
        finding_id="finding-01",
        expected_revision=fixed.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )
    tampered = original.model_copy(update={"sha256": "9" * 64})

    with pytest.raises(GovernedRetestError, match="original evidence"):
        service.record(
            finding_id="finding-01",
            retest_id=started.retest_plans[-1].retest_id,
            expected_revision=started.revision,
            before_evidence=(tampered,),
            after_evidence=(),
            check_receipts=(),
            original_issue_blocked=None,
            regression_free=None,
        )

    assert tuple(service.receipt_store.root.glob("*.json")) == ()


def test_retest_start_requires_latest_fixed_verdict(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    store.create(
        Finding(
            finding_id="finding-01",
            campaign_id="campaign-01",
            fingerprint="a" * 64,
            title="Unready finding",
            description="This finding has not completed governed remediation verification.",
            severity=FindingSeverity.MEDIUM,
            confidence=70,
            verification=VerificationState.VERIFIED,
            affected_asset="repo-01",
            evidence=(
                _evidence(
                    "evidence-original",
                    "b",
                    "independently reviewed original evidence",
                ),
            ),
            created_at=NOW,
            updated_at=NOW,
        )
    )
    service = GovernedRetestService(
        finding_store=store,
        receipt_store=RetestReceiptStore(tmp_path / "retest-receipts"),
        clock=lambda: NOW + timedelta(minutes=1),
    )

    with pytest.raises(FindingLifecycleError, match="ready-for-retest"):
        service.start(
            finding_id="finding-01",
            expected_revision=0,
            owner_id="retest-operator",
            check_references=("bounded check",),
            expires_at=NOW + timedelta(days=1),
        )
