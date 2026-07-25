from __future__ import annotations

from datetime import UTC, datetime

from vulnhunter.hunt.mobile_runtime import run_mobile_evidence_hunt
from vulnhunter.hunt.models import CandidateState, HuntAltitude
from vulnhunter.mobile.static_worker import MobileStaticAnalysisResult, MobileToolCapture


def test_mobile_hunt_verifies_evidence_requires_depth_and_rejects_tool_noise():
    result = MobileStaticAnalysisResult(
        artifact_id="apk-runtime-test",
        state="completed",
        captures=(
            MobileToolCapture(
                tool="apktool",
                return_code=0,
                output="decoded",
                output_sha256="a" * 64,
                truncated=False,
            ),
            MobileToolCapture(
                tool="jadx",
                return_code=1,
                output="failed",
                output_sha256="b" * 64,
                truncated=False,
            ),
        ),
        candidate_observations=(
            {
                "observation_id": "manifest-debuggable",
                "weakness_id": "masvs-resilience-debuggable",
                "title": "Application is debuggable",
                "severity": "medium",
                "status": "verified_configuration",
                "component": "application",
                "evidence": {"android:debuggable": "true"},
                "tool_ids": ["apktool-manifest"],
            },
            {
                "observation_id": "mobile-native-present",
                "title": "APK contains native libraries",
                "status": "evidence_required",
                "count": 2,
                "abis": ["arm64-v8a"],
            },
            {
                "observation_id": "mobile-tool-jadx",
                "title": "jadx could not complete static inspection",
                "status": "operational_failure",
                "return_code": 1,
            },
        ),
        completed_at=datetime(2026, 7, 25, 12, 0, tzinfo=UTC),
        reason="Read-only static APK inspection completed.",
    )

    receipt = run_mobile_evidence_hunt(result)
    states = {item.candidate_id: item.state for item in receipt.candidates}

    assert receipt.iterations == 2
    assert receipt.verified_count == 1
    assert receipt.evidence_required_count == 1
    assert receipt.rejected_count == 1
    assert states["manifest-debuggable"] == CandidateState.VERIFIED
    assert states["mobile-native-present"] == CandidateState.EVIDENCE_REQUIRED
    assert states["mobile-tool-jadx"] == CandidateState.REJECTED
    assert CandidateState.CONFIRMED not in states.values()
    assert receipt.rounds[0].altitude == HuntAltitude.VERIFICATION
    assert receipt.rounds[1].altitude == HuntAltitude.VARIANT_SWEEP
    assert receipt.rounds[1].net_new_count == 0
    assert "no net-new" in receipt.stop_reason.casefold()
    assert len(receipt.receipt_sha256) == 64
