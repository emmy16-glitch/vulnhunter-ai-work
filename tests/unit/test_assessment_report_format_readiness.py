from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunter.web.selected_assessment_projection import selected_assessment_projection

SCRIPT = Path("vulnhunter/web/static/web/conversation-mobile-inspector.js")


def _projection(
    *,
    kind: str = "apk",
    state: str = "completed",
    report_ready: bool = False,
    verified_count: int = 0,
    evidence_count: int = 0,
) -> dict[str, object]:
    assessment_id = f"assessment-{kind}"
    surfaces = {
        name: assessment_id
        for name in (
            "activity",
            "chat",
            "evidence",
            "findings",
            "graph",
            "history",
            "inspector",
            "reports",
        )
    }
    result_identity = {
        name: assessment_id for name in ("evidence", "findings", "graph", "reports")
    }
    return {
        "assessment_id": assessment_id,
        "assessment_kind": kind,
        "graph_id": f"graph-{kind}",
        "selected": True,
        "projection_revision": 3,
        "surface_identity": surfaces,
        "result_identity": result_identity,
        "subject": {"label": f"{kind} target"},
        "lifecycle": "report_ready" if report_ready else "awaiting_verification",
        "task_card": {
            "assessment_id": assessment_id,
            "activity_timeline_id": f"activity-{assessment_id}",
            "state": state,
            "terminal": state
            in {"blocked", "failed", "gated", "rejected", "completed", "cancelled"},
            "progress": {
                "measurement": "stage",
                "completed": 8 if state == "completed" else 4,
                "total": 8,
                "stage": "report" if state == "completed" else "verification",
            },
        },
        "execution": {"state": state},
        "health": {
            "assessment": "completed" if state == "completed" else "in_progress",
            "worker": "available" if state == "completed" else "active",
            "provider": "not_evaluated",
        },
        "findings": {
            "candidate_count": verified_count,
            "rejected_count": 0,
            "verified_count": verified_count,
            "abstained_count": 0,
        },
        "evidence": {"record_count": evidence_count},
        "report": {
            "ready": report_ready,
            "status": "ready" if report_ready else "pending",
            "stage_status": "completed" if report_ready else "pending",
            "report_id": f"{assessment_id}-report" if report_ready else None,
            "digest": "a" * 64 if report_ready else None,
        },
    }


@pytest.mark.parametrize("kind", ["apk", "website", "source_hunt"])
def test_every_workflow_exposes_the_same_five_report_format_rows(kind: str) -> None:
    projected = selected_assessment_projection(_projection(kind=kind))

    assert projected is not None
    formats = projected["report"]["formats"]
    assert tuple(formats) == ("html", "json", "sarif", "evidence_zip", "pdf")
    assert formats["html"]["status"] == "unavailable"
    assert formats["json"]["status"] == "available"
    assert formats["sarif"]["status"] == "unavailable"
    assert formats["evidence_zip"]["status"] == "unavailable"
    assert formats["pdf"]["status"] == "unavailable"
    assert all(item["reason"] for item in formats.values())


def test_ready_persisted_report_makes_only_supported_html_and_json_available() -> None:
    projected = selected_assessment_projection(
        _projection(report_ready=True, verified_count=2, evidence_count=3)
    )

    assert projected is not None
    formats = projected["report"]["formats"]
    assert formats["html"] == {
        "status": "available",
        "reason": "Persisted evidence-backed assessment report is ready.",
    }
    assert formats["json"]["status"] == "available"
    assert formats["sarif"] == {
        "status": "unavailable",
        "reason": "SARIF export is not implemented for selected assessments.",
    }
    assert formats["evidence_zip"] == {
        "status": "unavailable",
        "reason": "Preserved evidence exists, but Evidence ZIP packaging is not implemented.",
    }
    assert formats["pdf"]["status"] == "unavailable"


def test_unavailable_export_reasons_reflect_missing_verified_findings_and_evidence() -> None:
    projected = selected_assessment_projection(_projection())

    assert projected is not None
    formats = projected["report"]["formats"]
    assert "No verified findings are available" in formats["sarif"]["reason"]
    assert "No preserved evidence is available" in formats["evidence_zip"]["reason"]
    assert formats["pdf"]["reason"] == "PDF rendering is not configured for selected assessments."


def test_browser_renders_server_report_format_contract_without_inventing_readiness() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "const report = state.projection?.report || {}" in script
    assert 'const formats = report.formats && typeof report.formats === "object"' in script
    for token in (
        '["html", "HTML"]',
        '["json", "JSON"]',
        '["sarif", "SARIF"]',
        '["evidence_zip", "Evidence ZIP"]',
        '["pdf", "PDF"]',
    ):
        assert token in script
    report_block = script.split("const updateReports = () => {", 1)[1].split(
        "const updateProgress = () => {", 1
    )[0]
    assert "resultSummary().report" not in report_block
    assert 'status === "available"' in report_block
    assert "row.value.reason" in report_block
    assert "selectedAssessmentId()" in report_block
