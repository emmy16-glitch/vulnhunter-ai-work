import json
import zipfile

import pytest

from vulnhunter.reports import DownloadFormat, ReportExporter, ReportExportError


def test_report_exporter_builds_json_html_sarif_and_svg(tmp_path):
    exporter = ReportExporter(tmp_path / "out")
    payload = {"finding": {"title": "IDOR", "verification": "verified"}}
    json_artifact = exporter.export_json(
        artifact_id="report-01", payload=payload, provenance=("finding-01",)
    )
    html_artifact = exporter.export_html(
        artifact_id="report-02", title="Assessment", payload=payload, provenance=("finding-01",)
    )
    exporter.export_sarif(
        artifact_id="report-03",
        findings=(
            {
                "title": "IDOR",
                "description": "Object access issue",
                "severity": "high",
                "path": "api.py",
                "line": 4,
            },
        ),
        provenance=("finding-01",),
    )
    svg = exporter.export_attack_path_svg(
        artifact_id="path-01", nodes=("Internet", "API", "User data"), provenance=("path-01",)
    )
    assert json_artifact.format == DownloadFormat.JSON
    assert html_artifact.size_bytes > 0
    assert json.loads((tmp_path / "out" / "report-03.sarif.json").read_text())["version"] == "2.1.0"
    assert svg.sha256


def test_report_exporter_rejects_recursive_secrets_and_unsafe_evidence(tmp_path):
    exporter = ReportExporter(tmp_path / "out")
    with pytest.raises(ValueError, match="protected"):
        exporter.export_json(
            artifact_id="bad", payload={"nested": [{"api_key": "x"}]}, provenance=()
        )
    outside = tmp_path / "outside.txt"
    outside.write_text("evidence", encoding="utf-8")
    approved = tmp_path / "approved"
    approved.mkdir()
    with pytest.raises(ReportExportError, match="outside"):
        exporter.export_evidence_zip(
            artifact_id="evidence-01",
            evidence_files=(outside,),
            manifest={"campaign": "c"},
            provenance=(),
            approved_roots=(approved,),
        )


@pytest.mark.parametrize(
    ("content", "secret"),
    (
        ("Authorization: Bearer test-token", "test-token"),
        ("Cookie: sessionid=test-session", "test-session"),
        ("password=test-password", "test-password"),
    ),
)
def test_evidence_zip_rejects_protected_data_without_persisting_archive(
    tmp_path,
    content,
    secret,
):
    approved = tmp_path / "approved"
    approved.mkdir()
    evidence = approved / "response.txt"
    evidence.write_text(content, encoding="utf-8")
    exporter = ReportExporter(tmp_path / "out")

    with pytest.raises(ReportExportError, match="protected data") as exc_info:
        exporter.export_evidence_zip(
            artifact_id="evidence-protected",
            evidence_files=(evidence,),
            manifest={"campaign": "campaign-01"},
            provenance=("evidence-01",),
            approved_roots=(approved,),
        )

    assert secret not in str(exc_info.value)
    assert not (tmp_path / "out" / "evidence-protected.zip").exists()
    assert not (tmp_path / "out" / "evidence-protected.zip.tmp").exists()


def test_evidence_zip_contains_hash_manifest(tmp_path):
    approved = tmp_path / "approved"
    approved.mkdir()
    evidence = approved / "response.txt"
    evidence.write_text("safe evidence", encoding="utf-8")
    exporter = ReportExporter(tmp_path / "out")
    artifact = exporter.export_evidence_zip(
        artifact_id="evidence-02",
        evidence_files=(evidence,),
        manifest={"campaign": "campaign-01"},
        provenance=("evidence-01",),
        approved_roots=(approved,),
    )
    with zipfile.ZipFile(artifact.path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["entries"][0]["sha256"]
