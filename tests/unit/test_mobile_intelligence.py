import hashlib
from datetime import UTC, datetime

from vulnhunter.hunt.mobile_runtime import run_mobile_evidence_hunt
from vulnhunter.mobile.intelligence import (
    MobileEvidenceState,
    MobileToolExecutionStatus,
    build_mobile_intelligence,
    build_mobile_intelligence_context,
    detect_dynamic_endpoint_assignments,
)
from vulnhunter.mobile.static_toolchain import MobileToolCapture
from vulnhunter.mobile.static_worker import MobileStaticAnalysisResult

NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
ARTIFACT_SHA256 = "a" * 64


def _capture(tool: str, *, return_code: int = 0, evidence: dict[str, object] | None = None):
    return MobileToolCapture(
        tool=tool,
        return_code=return_code,
        output="bounded tool output",
        output_sha256=hashlib.sha256(tool.encode()).hexdigest(),
        truncated=False,
        started_at=NOW,
        completed_at=NOW,
        duration_ms=100,
        evidence=evidence or {},
    )


def _observations() -> tuple[dict[str, object], ...]:
    return (
        {
            "observation_id": "obs-cleartext",
            "weakness_id": "android-cleartext-traffic",
            "title": "Application permits cleartext traffic",
            "severity": "high",
            "status": "verified_configuration",
            "evidence": {"tool": "apktool", "source_file": "AndroidManifest.xml"},
        },
        {
            "observation_id": "obs-webview",
            "weakness_id": "android-webview-javascript-bridge",
            "title": "WebView JavaScript bridge candidate",
            "severity": "medium",
            "status": "evidence_required",
            "component": "com.example.v380.LoginActivity",
            "evidence": {"tool": "yara", "source_file": "classes.dex"},
        },
        {
            "observation_id": "obs-endpoints",
            "weakness_id": "mobile-dynamic-endpoint-assignment",
            "title": "App assigns server endpoints from network data",
            "severity": "medium",
            "status": "evidence_required",
            "component": "com.example.v380.GlobalDefines",
            "evidence": {"tool": "jadx", "source_file": "GlobalDefines.java"},
        },
        {
            "observation_id": "obs-tool-failure",
            "title": "jadx could not complete static inspection",
            "status": "operational_failure",
            "evidence": {"tool": "jadx"},
        },
    )


def test_intelligence_separates_findings_candidates_and_operational_issues():
    intelligence = build_mobile_intelligence(
        artifact_sha256=ARTIFACT_SHA256,
        observations=_observations(),
        captures=(
            _capture("apktool"),
            _capture("jadx", return_code=124, evidence={"generated_files": 41_622}),
        ),
        layered_report={
            "manifest": {"package_name": "com.example.v380"},
            "network_endpoints": [
                {
                    "endpoint": "http://example.test/update",
                    "protocol": "http",
                    "source_file": "com/example/v380/Update.java",
                    "source_offset": 10,
                    "likely_role": "firmware_update",
                },
                {
                    "endpoint": "http://example.test/update/",
                    "protocol": "http",
                    "source_file": "com/example/v380/Config.java",
                    "source_offset": 20,
                    "likely_role": "firmware_update",
                },
            ],
        },
        planned_tools=("apktool", "jadx", "radare2", "ghidra"),
        native_library_count=0,
    )

    assert intelligence.observation_count == 4
    assert intelligence.verified_configuration_count == 1
    assert intelligence.verified_security_finding_count == 0
    assert intelligence.evidence_required_count == 2
    assert intelligence.operational_issue_count == 2
    assert len(intelligence.endpoint_references) == 1
    assert len(intelligence.endpoint_references[0].source_references) == 2
    assert intelligence.coverage.capabilities[-3].status == MobileToolExecutionStatus.NOT_APPLICABLE
    assert intelligence.coverage.capabilities[-1].status == MobileToolExecutionStatus.BLOCKED
    assert any(
        item.evidence_state == MobileEvidenceState.PARTIAL_TOOL_RESULT
        for item in intelligence.operational_issues
    )
    assert len(intelligence.hypotheses) == 2
    assert intelligence.intelligence_sha256 and len(intelligence.intelligence_sha256) == 64
    assert "output" not in str(intelligence.ai_context).casefold()
    assert any(
        "JADX partial coverage" in item
        for item in intelligence.ai_context["bounded_negative_rules"]
    )


def test_ai_context_is_bounded_and_provider_neutral():
    intelligence = build_mobile_intelligence(
        artifact_sha256=ARTIFACT_SHA256,
        observations=_observations(),
        captures=(_capture("jadx", return_code=124, evidence={"generated_files": 10}),),
        layered_report={"manifest": {"package_name": "com.example.v380"}},
        planned_tools=("jadx",),
        native_library_count=0,
    )

    context = build_mobile_intelligence_context(intelligence)

    assert context["artifact_sha256"] == ARTIFACT_SHA256
    assert context["tool_limitations"][0]["status"] == "partial"
    assert "output" not in str(context).casefold()
    assert "provider" not in str(context).casefold()


def test_malformed_endpoint_literal_is_retained_without_invalidating_receipt():
    intelligence = build_mobile_intelligence(
        artifact_sha256=ARTIFACT_SHA256,
        observations=(),
        captures=(),
        layered_report={
            "manifest": {"package_name": "com.example.v380"},
            "network_endpoints": [
                {
                    "endpoint": "https://bad.example:invalid-port/path",
                    "protocol": "https",
                    "source_file": "com/example/v380/Config.java",
                }
            ],
        },
        planned_tools=(),
        native_library_count=0,
    )

    assert len(intelligence.endpoint_references) == 1
    assert intelligence.endpoint_references[0].host == "bad.example"
    assert intelligence.endpoint_references[0].port is None


def test_dynamic_endpoint_assignment_detector_is_generic_and_evidence_required():
    observations = detect_dynamic_endpoint_assignments(
        (
            {
                "source_file": "com/example/Config.java",
                "class_name": "com.example.Config",
                "text": "String response = fetch();\nserverEndpoint = response.url;",
                "source_kind": "network_response",
            },
        )
    )

    assert len(observations) == 1
    assert observations[0]["weakness_id"] == "mobile-dynamic-endpoint-assignment"
    assert observations[0]["status"] == "evidence_required"
    assert observations[0]["evidence"]["destination"] == "serverEndpoint"


def test_operational_issues_do_not_enter_evidence_hunt_candidates():
    intelligence = build_mobile_intelligence(
        artifact_sha256=ARTIFACT_SHA256,
        observations=_observations(),
        captures=(_capture("jadx", return_code=124),),
        layered_report={"manifest": {"package_name": "com.example.v380"}},
        planned_tools=("jadx",),
        native_library_count=0,
    )
    result = MobileStaticAnalysisResult(
        artifact_id="apk-0123456789abcdef01234567",
        state="completed",
        captures=(_capture("jadx", return_code=124),),
        candidate_observations=_observations(),
        intelligence=intelligence,
        completed_at=NOW,
        reason="Static analysis completed with bounded tool results.",
    )

    hunt = run_mobile_evidence_hunt(result)

    assert len(hunt.candidates) == 2
    assert all(item.source_status == "evidence_required" for item in hunt.candidates)
    assert hunt.rejected_count == 0
