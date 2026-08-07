from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.hunt.mobile_runtime import MobileHuntExecutionReceipt
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_service import (
    _report_summary,
    _review_summary,
    _verification_summary,
    create_mobile_static_job,
)

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)


def _hunt(*, verified: int, rejected: int, abstained: int) -> MobileHuntExecutionReceipt:
    return MobileHuntExecutionReceipt(
        iterations=2,
        rounds=(),
        candidates=(),
        verified_count=verified,
        rejected_count=rejected,
        evidence_required_count=abstained,
        stop_reason="Bounded deterministic verification completed.",
        receipt_sha256="a" * 64,
    )


def _artifact(tmp_path: Path) -> MobileArtifactRecord:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk")
    return MobileArtifactRecord(
        artifact_id="apk-0123456789abcdef01234567",
        original_filename="app.apk",
        stored_path=apk,
        sha256="b" * 64,
        size_bytes=3,
        archive_entry_count=2,
        total_uncompressed_bytes=3,
        manifest_entry="AndroidManifest.xml",
        dex_entries=("classes.dex",),
        native_libraries=(),
        native_abis=(),
    )


def test_empty_candidate_set_abstains_instead_of_inventing_a_verified_finding():
    verification = _verification_summary(_hunt(verified=0, rejected=0, abstained=0))

    assert verification == {
        "status": "abstained",
        "verified_count": 0,
        "rejected_count": 0,
        "abstained_count": 0,
        "reason": "No candidate vulnerability was generated; verification completed without a claim.",
    }


def test_deterministic_review_receipt_cannot_claim_finding_or_publication_authority():
    hunt = _hunt(verified=0, rejected=0, abstained=0)
    verification = _verification_summary(hunt)

    review = _review_summary(hunt=hunt, verification=verification)

    assert review["status"] == "completed"
    assert len(review["receipt_sha256"]) == 64
    assert review["summary"]["finding_confirmation"] is False
    assert review["summary"]["publication_authority"] is False
    assert review["summary"]["scope"] == "deterministic_evidence_disposition"


def test_report_identity_is_deterministic_and_bound_to_assessment_artifact_hunt_and_review(
    tmp_path,
):
    key = b"r" * 48
    job = create_mobile_static_job(
        run_id="mobile-report-01",
        artifact_id="apk-0123456789abcdef01234567",
        artifact_sha256="b" * 64,
        hunt_plan_sha256="c" * 64,
        requested_by="mobile-analyst",
        signing_key=key,
        now=NOW,
    )
    artifact = _artifact(tmp_path)
    hunt = _hunt(verified=0, rejected=0, abstained=0)
    verification = _verification_summary(hunt)
    review = _review_summary(hunt=hunt, verification=verification)

    first = _report_summary(
        job=job,
        artifact=artifact,
        hunt=hunt,
        verification=verification,
        review=review,
    )
    second = _report_summary(
        job=job,
        artifact=artifact,
        hunt=hunt,
        verification=verification,
        review=review,
    )

    assert first == second
    assert first["status"] == "ready"
    assert first["report_id"].startswith("mobile-report-01-report-")
    assert len(first["digest"]) == 64
    assert first["summary"]["assessment_id"] == job.run_id
    assert first["summary"]["artifact_sha256"] == artifact.sha256
    assert first["summary"]["hunt_receipt_sha256"] == hunt.receipt_sha256
    assert first["summary"]["review_receipt_sha256"] == review["receipt_sha256"]
