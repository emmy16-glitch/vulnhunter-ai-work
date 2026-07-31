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
    RemediationState,
    RetestRecord,
    VerificationState,
)

NOW = datetime(2026, 7, 31, 20, 0, tzinfo=UTC)


def _finding(*, verified: bool = False):
    return Finding(
        finding_id="finding-01",
        campaign_id="campaign-01",
        fingerprint=Finding.create_fingerprint(
            campaign_id="campaign-01",
            title="IDOR",
            affected_asset="api.example",
            affected_component="/users/{id}",
        ),
        title="IDOR",
        description="User lookup may expose another user's record.",
        severity=FindingSeverity.HIGH,
        confidence=80,
        verification=(VerificationState.VERIFIED if verified else VerificationState.OBSERVED),
        affected_asset="api.example",
        affected_component="/users/{id}",
        evidence=(
            EvidenceReference(
                evidence_id="evidence-01",
                sha256="a" * 64,
                provenance="nuclei output",
                content_type="text/plain",
            ),
        ),
    )


def test_finding_store_deduplicates_and_uses_revision_cas(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    finding = _finding()
    store.create(finding)
    with pytest.raises(FindingConflict):
        store.create(finding.model_copy(update={"finding_id": "finding-02"}))
    service = FindingService(store)
    verified = service.update_verification(
        "finding-01",
        verification=VerificationState.VERIFIED,
        analyst_decision="Evidence and independent review confirm the issue.",
        expected_revision=0,
    )
    assert verified.revision == 1
    with pytest.raises(FindingConflict):
        service.update_verification(
            "finding-01",
            verification=VerificationState.FALSE_POSITIVE,
            analyst_decision="Stale writer must lose.",
            expected_revision=0,
        )


def test_verified_finding_starts_exact_governed_remediation(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    store.create(_finding(verified=True))

    updated = FindingService(store).start_remediation(
        "finding-01",
        owner_id="developer-01",
        summary="Enforce object ownership before returning the requested user record.",
        target_references=("app/users.py", "GET /users/{id}"),
        regression_test="The cross-user request must fail before the fix and pass after the fix.",
        verification_recipe="Run the read-only security test and the complete user API regression suite.",
        compatibility_risks=("Existing administrative access must remain available.",),
        references=("evidence-01",),
        expires_at=NOW + timedelta(days=7),
        expected_revision=0,
        now=NOW,
    )

    assert updated.status == FindingStatus.IN_REMEDIATION
    assert updated.revision == 1
    remediation = updated.remediation
    assert remediation is not None
    assert remediation.state == RemediationState.READY_FOR_IMPLEMENTATION
    assert remediation.source_finding_revision == 0
    assert remediation.source_finding_fingerprint == updated.fingerprint
    assert remediation.plan_sha256 is not None and len(remediation.plan_sha256) == 64
    assert remediation.target_references == ("app/users.py", "GET /users/{id}")


def test_remediation_rejects_unverified_findings_and_stale_writers(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    store.create(_finding())
    service = FindingService(store)
    values = {
        "owner_id": "developer-01",
        "summary": "Enforce ownership before returning the selected record.",
        "target_references": ("app/users.py",),
        "regression_test": "A cross-user request must be rejected.",
        "verification_recipe": "Run the bounded security test and regression suite.",
        "expires_at": NOW + timedelta(days=7),
        "now": NOW,
    }

    with pytest.raises(FindingLifecycleError, match="independently verified"):
        service.start_remediation("finding-01", expected_revision=0, **values)

    verified = service.update_verification(
        "finding-01",
        verification=VerificationState.VERIFIED,
        analyst_decision="Independent review confirms the evidence.",
        expected_revision=0,
    )
    assert verified.revision == 1
    with pytest.raises(FindingConflict):
        service.start_remediation("finding-01", expected_revision=0, **values)


def test_cancellation_is_terminal_and_returns_finding_to_triage(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    store.create(_finding(verified=True))
    service = FindingService(store)
    started = service.start_remediation(
        "finding-01",
        owner_id="developer-01",
        summary="Enforce ownership before returning the selected record.",
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected.",
        verification_recipe="Run the bounded security test and regression suite.",
        expires_at=NOW + timedelta(days=7),
        expected_revision=0,
        now=NOW,
    )

    cancelled = service.cancel_remediation(
        "finding-01",
        reason="Owner withdrew the plan before implementation.",
        expected_revision=started.revision,
        now=NOW + timedelta(minutes=5),
    )

    assert cancelled.status == FindingStatus.TRIAGED
    assert cancelled.remediation is not None
    assert cancelled.remediation.state == RemediationState.CANCELLED
    assert cancelled.remediation.cancellation_reason == (
        "Owner withdrew the plan before implementation."
    )
    with pytest.raises(FindingLifecycleError, match="no active"):
        service.cancel_remediation(
            "finding-01",
            reason="A terminal plan cannot be cancelled again.",
            expected_revision=cancelled.revision,
            now=NOW + timedelta(minutes=10),
        )


def test_passed_retest_marks_finding_remediated(tmp_path):
    store = FindingStore(tmp_path / "findings.sqlite3")
    store.create(_finding())
    service = FindingService(store)
    result = service.append_retest(
        "finding-01",
        expected_revision=0,
        retest=RetestRecord(
            retest_id="retest-01",
            performed_by="analyst-01",
            performed_at=datetime(2026, 7, 15, tzinfo=UTC),
            outcome="passed",
            evidence=(
                EvidenceReference(
                    evidence_id="evidence-02",
                    sha256="b" * 64,
                    provenance="bounded retest",
                    content_type="application/json",
                ),
            ),
            notes="The original bounded request no longer reproduces the issue.",
        ),
    )
    assert result.status == FindingStatus.REMEDIATED
