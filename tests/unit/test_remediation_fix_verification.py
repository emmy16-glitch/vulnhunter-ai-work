from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingConflict,
    FindingService,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RemediationFixVerificationError,
    RemediationFixVerificationService,
    RemediationFixVerificationStore,
    RemediationState,
    VerificationState,
)
from vulnhunter.source_hunt import (
    FixVerificationVerdict,
    RepositorySnapshot,
    SourceReference,
    VerifierReceipt,
)
from vulnhunter.source_hunt.models import RepositoryFile

NOW = datetime(2026, 7, 31, 21, 30, tzinfo=UTC)


def _finding() -> Finding:
    return Finding(
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
        evidence=(
            EvidenceReference(
                evidence_id="source-evidence-01",
                sha256="a" * 64,
                provenance="independently reviewed source evidence",
                content_type="application/json",
            ),
        ),
        created_at=NOW - timedelta(hours=2),
        updated_at=NOW - timedelta(hours=2),
    )


def _snapshot(*, revision: str, source_sha256: str) -> RepositorySnapshot:
    return RepositorySnapshot(
        repository_id="repo-01",
        repository_root="/approved/repo-01",
        revision=revision,
        snapshot_sha256=hashlib.sha256(f"snapshot:{revision}".encode()).hexdigest(),
        files=(
            RepositoryFile(
                path="app/users.py",
                sha256=source_sha256,
                size_bytes=120,
                language="python",
                line_count=20,
            ),
        ),
        total_bytes=120,
        created_at=NOW,
    )


def _receipt(name: str, *, passed: bool = True) -> VerifierReceipt:
    return VerifierReceipt(
        verifier_id=name,
        passed=passed,
        exit_code=0 if passed else 1,
        output_sha256=hashlib.sha256(f"{name}:{passed}".encode()).hexdigest(),
        duration_seconds=0.25,
        safe_summary="Deterministic verifier completed with bounded redacted output.",
    )


def _service(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    store.create(_finding())
    planned = FindingService(store).start_remediation(
        "finding-01",
        owner_id="remediation-owner",
        summary="Enforce object ownership before returning the selected user record.",
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected by the RED security test.",
        verification_recipe="Run the independent read-only security and regression receipts.",
        references=("source-evidence-01",),
        expires_at=NOW + timedelta(days=7),
        expected_revision=0,
        now=NOW,
    )
    receipt_store = RemediationFixVerificationStore(tmp_path / "fix-verification")
    service = RemediationFixVerificationService(
        finding_store=store,
        receipt_store=receipt_store,
        clock=lambda: NOW + timedelta(minutes=5),
    )
    return store, planned, receipt_store, service


def _fixed_evidence(snapshot: RepositorySnapshot) -> tuple[SourceReference, ...]:
    file = snapshot.files[0]
    return (
        SourceReference(
            path=file.path,
            source_sha256=file.sha256,
            line_start=1,
            line_end=12,
            symbol="get_user",
        ),
    )


def test_fixed_verdict_atomically_advances_finding_and_persists_receipt(tmp_path):
    store, planned, receipt_store, service = _service(tmp_path)
    original = _snapshot(revision="1" * 40, source_sha256="b" * 64)
    fixed = _snapshot(revision="2" * 40, source_sha256="c" * 64)

    updated, bundle = service.record(
        finding_id="finding-01",
        expected_revision=planned.revision,
        builder_id="developer-01",
        allowed_paths=("app/users.py",),
        changed_files=("app/users.py",),
        original_snapshot=original,
        fixed_snapshot=fixed,
        security_test=_receipt("security-red"),
        regression_tests=(_receipt("pytest"), _receipt("ruff")),
        fixed_evidence_refs=_fixed_evidence(fixed),
        original_attack_blocked=True,
    )

    assert updated.status == FindingStatus.READY_FOR_RETEST
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.READY_FOR_RETEST
    assert len(updated.remediation.verification_history) == 1
    reference = updated.remediation.verification_history[0]
    assert reference.receipt_id == bundle.receipt_id
    assert reference.verdict == FixVerificationVerdict.FIXED.value
    assert reference.original_revision == original.revision
    assert reference.fixed_revision == fixed.revision
    assert store.get("finding-01") == updated
    assert receipt_store.load(bundle.receipt_id) == bundle
    assert updated.evidence[-1].evidence_id == bundle.receipt_id
    assert updated.evidence[-1].sha256 == bundle.fingerprint()


def test_non_fixed_attempt_requires_rework_and_later_fixed_attempt_is_append_only(tmp_path):
    _store, planned, receipt_store, service = _service(tmp_path)
    original = _snapshot(revision="3" * 40, source_sha256="d" * 64)
    first_fixed = _snapshot(revision="4" * 40, source_sha256="e" * 64)

    needs_rework, first_bundle = service.record(
        finding_id="finding-01",
        expected_revision=planned.revision,
        builder_id="developer-01",
        allowed_paths=("app/users.py",),
        changed_files=("app/users.py",),
        original_snapshot=original,
        fixed_snapshot=first_fixed,
        security_test=_receipt("security-red", passed=False),
        regression_tests=(_receipt("pytest"),),
        fixed_evidence_refs=(),
        original_attack_blocked=False,
    )

    assert needs_rework.status == FindingStatus.IN_REMEDIATION
    assert needs_rework.remediation is not None
    assert needs_rework.remediation.state == RemediationState.NEEDS_REWORK
    assert needs_rework.remediation.verification_history[-1].verdict == "not_fixed"

    second_fixed = _snapshot(revision="5" * 40, source_sha256="f" * 64)
    ready, second_bundle = service.record(
        finding_id="finding-01",
        expected_revision=needs_rework.revision,
        builder_id="developer-02",
        allowed_paths=("app/users.py",),
        changed_files=("app/users.py",),
        original_snapshot=original,
        fixed_snapshot=second_fixed,
        security_test=_receipt("security-red"),
        regression_tests=(_receipt("pytest"),),
        fixed_evidence_refs=_fixed_evidence(second_fixed),
        original_attack_blocked=True,
    )

    assert ready.status == FindingStatus.READY_FOR_RETEST
    assert ready.remediation is not None
    assert ready.remediation.state == RemediationState.READY_FOR_RETEST
    assert [item.receipt_id for item in ready.remediation.verification_history] == [
        first_bundle.receipt_id,
        second_bundle.receipt_id,
    ]
    assert receipt_store.load(first_bundle.receipt_id) == first_bundle
    assert receipt_store.load(second_bundle.receipt_id) == second_bundle


def test_stale_finding_revision_loses_and_does_not_leave_orphan_receipt(tmp_path):
    _store, planned, receipt_store, service = _service(tmp_path)
    original = _snapshot(revision="6" * 40, source_sha256="1" * 64)
    fixed = _snapshot(revision="7" * 40, source_sha256="2" * 64)

    with pytest.raises(FindingConflict):
        service.record(
            finding_id="finding-01",
            expected_revision=planned.revision - 1,
            builder_id="developer-01",
            allowed_paths=("app/users.py",),
            changed_files=("app/users.py",),
            original_snapshot=original,
            fixed_snapshot=fixed,
            security_test=_receipt("security-red"),
            regression_tests=(_receipt("pytest"),),
            fixed_evidence_refs=_fixed_evidence(fixed),
            original_attack_blocked=True,
        )

    assert tuple(receipt_store.root.glob("*.json")) == ()


def test_handoff_cannot_expand_plan_paths_or_impersonate_independent_verifier(tmp_path):
    _store, planned, _receipt_store, service = _service(tmp_path)
    original = _snapshot(revision="8" * 40, source_sha256="3" * 64)
    fixed = _snapshot(revision="9" * 40, source_sha256="4" * 64)

    with pytest.raises(RemediationFixVerificationError, match="approved remediation targets"):
        service.record(
            finding_id="finding-01",
            expected_revision=planned.revision,
            builder_id="developer-01",
            allowed_paths=("app/admin.py",),
            changed_files=("app/admin.py",),
            original_snapshot=original,
            fixed_snapshot=fixed,
            security_test=_receipt("security-red"),
            regression_tests=(_receipt("pytest"),),
            fixed_evidence_refs=(),
            original_attack_blocked=True,
        )

    with pytest.raises(RemediationFixVerificationError, match="independent"):
        service.record(
            finding_id="finding-01",
            expected_revision=planned.revision,
            builder_id="read-only-fix-verifier",
            allowed_paths=("app/users.py",),
            changed_files=("app/users.py",),
            original_snapshot=original,
            fixed_snapshot=fixed,
            security_test=_receipt("security-red"),
            regression_tests=(_receipt("pytest"),),
            fixed_evidence_refs=_fixed_evidence(fixed),
            original_attack_blocked=True,
        )
