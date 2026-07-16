from datetime import UTC, datetime

import pytest

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingConflict,
    FindingService,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RetestRecord,
    VerificationState,
)


def _finding():
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
