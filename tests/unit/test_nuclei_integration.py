import json
from datetime import UTC, datetime

import pytest

from vulnhunter.security_tools.adapters import build_command_plan
from vulnhunter.security_tools.catalog import default_catalog
from vulnhunter.security_tools.integration import normalize_execution_findings
from vulnhunter.security_tools.models import (
    SecurityToolRequest,
    ToolExecutionResult,
    ToolProfile,
)
from vulnhunter.security_tools.nuclei import NucleiPolicyError


def _request(tmp_path, **updates):
    values = {
        "request_id": "nuclei-request",
        "action_manifest_sha256": "a" * 64,
        "tool_id": "nuclei",
        "profile": ToolProfile.SAFE_ASSESSMENT,
        "operation": "scan",
        "target": "https://example.test",
        "timeout_seconds": 90,
        "maximum_output_bytes": 500_000,
        "output_directory": tmp_path / "evidence",
        "parameters": {},
    }
    values.update(updates)
    return SecurityToolRequest(**values)


def test_passive_plan_enforces_signed_cloud_free_low_resource_baseline(tmp_path):
    plan = build_command_plan(
        _request(tmp_path),
        executable="/opt/tools/nuclei",
        catalog=default_catalog(),
    )

    assert "-disable-unsigned-templates" in plan.argv
    assert "-disable-update-check" in plan.argv
    assert "-no-interactsh" in plan.argv
    assert "-restrict-local-network-access" in plan.argv
    assert "-jsonl-export" in plan.argv
    assert "-redact" in plan.argv
    assert plan.argv[plan.argv.index("-rate-limit") + 1] == "5"
    assert plan.argv[plan.argv.index("-bulk-size") + 1] == "2"
    assert plan.argv[plan.argv.index("-concurrency") + 1] == "2"
    assert "-headless" not in plan.argv
    assert "-code" not in plan.argv
    assert "-file" not in plan.argv
    assert "-dashboard" not in plan.argv
    assert "-cloud-upload" not in plan.argv
    assert "-prompt" not in plan.argv
    assert plan.requires_isolation is False


def test_standard_profile_requires_an_explicit_template_filter(tmp_path):
    request = _request(
        tmp_path,
        profile=ToolProfile.ACTIVE_ASSESSMENT,
        parameters={"scan_profile": "standard"},
    )
    with pytest.raises(NucleiPolicyError, match="explicit template IDs or tags"):
        build_command_plan(
            request,
            executable="/opt/tools/nuclei",
            catalog=default_catalog(),
        )


def test_intrusive_profile_requires_approval_and_marks_isolation(tmp_path):
    request = _request(
        tmp_path,
        profile=ToolProfile.ACTIVE_ASSESSMENT,
        parameters={
            "scan_profile": "intrusive",
            "template_ids": ["approved-cve-check"],
            "protocol_types": ["http", "headless"],
        },
    )
    with pytest.raises(NucleiPolicyError, match="exact human approval"):
        build_command_plan(
            request,
            executable="/opt/tools/nuclei",
            catalog=default_catalog(),
        )

    approved = request.model_copy(
        update={
            "parameters": {
                **request.parameters,
                "intrusive_approved": True,
            }
        }
    )
    plan = build_command_plan(
        approved,
        executable="/opt/tools/nuclei",
        catalog=default_catalog(),
    )
    assert plan.requires_isolation is True
    assert "-headless" in plan.argv
    assert plan.argv[plan.argv.index("-headless-concurrency") + 1] == "1"


def test_private_network_access_is_not_available_to_passive_profile(tmp_path):
    request = _request(
        tmp_path,
        parameters={"private_network_approved": True},
    )
    with pytest.raises(NucleiPolicyError, match="private-network access"):
        build_command_plan(
            request,
            executable="/opt/tools/nuclei",
            catalog=default_catalog(),
        )


def test_retest_requires_exact_template_ids(tmp_path):
    request = _request(
        tmp_path,
        profile=ToolProfile.RETEST,
        parameters={"scan_profile": "retest", "tags": ["cve"]},
    )
    with pytest.raises(NucleiPolicyError, match="exact approved template IDs"):
        build_command_plan(
            request,
            executable="/opt/tools/nuclei",
            catalog=default_catalog(),
        )


def test_blocked_capabilities_cannot_be_smuggled_as_parameters(tmp_path):
    request = _request(
        tmp_path,
        parameters={"raw_args": ["-dashboard"]},
    )
    with pytest.raises(NucleiPolicyError, match="blocked parameters"):
        build_command_plan(
            request,
            executable="/opt/tools/nuclei",
            catalog=default_catalog(),
        )


def test_nuclei_parser_preserves_safe_metadata_without_raw_exchange(tmp_path):
    output = tmp_path / "nuclei.jsonl"
    output.write_text(
        json.dumps(
            {
                "template-id": "example-check",
                "template": "http/misconfiguration/example.yaml",
                "matched-at": "https://example.test/admin?token=should-not-copy-query",
                "host": "https://example.test",
                "ip": "203.0.113.10",
                "type": "http",
                "matcher-name": "status-and-body",
                "timestamp": "2026-07-16T10:00:00Z",
                "info": {
                    "name": "Example exposure",
                    "severity": "medium",
                    "tags": ["exposure", "misconfig"],
                    "classification": {
                        "cwe-id": ["CWE-200"],
                        "cvss-score": 5.3,
                    },
                },
                "request": "Authorization: Bearer raw-secret",
                "response": "Set-Cookie: session=raw-secret",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    now = datetime.now(UTC)
    result = ToolExecutionResult(
        execution_id="execution-01",
        request_id="nuclei-request",
        tool_id="nuclei",
        command_plan_sha256="b" * 64,
        started_at=now,
        finished_at=now,
        return_code=0,
        timed_out=False,
        stdout_preview="",
        stderr_preview="",
        output_files=(str(output),),
        evidence_sha256="c" * 64,
        success=True,
    )

    findings = normalize_execution_findings(
        result,
        target_reference="https://example.test",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Example exposure"
    assert finding.severity == "medium"
    assert finding.confidence == "candidate"
    assert finding.evidence["template_id"] == "example-check"
    assert "request" not in finding.evidence
    assert "response" not in finding.evidence
    assert "raw-secret" not in json.dumps(finding.evidence)
    assert finding.evidence["matched_at"] == "https://example.test/admin"
