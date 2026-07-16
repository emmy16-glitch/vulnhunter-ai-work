import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.mobile import (
    MobileAnalysisProfile,
    MobileConnectorRequest,
    MobileConnectorType,
    build_mobile_connector_plan,
    parse_apkid_json,
    parse_mobsf_json,
)


def _request(tmp_path: Path, connector: MobileConnectorType, **updates):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"apk")
    values = {
        "request_id": "connector-request-01",
        "action_manifest_sha256": "a" * 64,
        "connector": connector,
        "profile": MobileAnalysisProfile.STATIC,
        "artifact_sha256": "b" * 64,
        "artifact_path": apk,
        "output_directory": tmp_path / "output",
    }
    values.update(updates)
    return MobileConnectorRequest(**values)


def test_frida_requires_dynamic_profile_isolation_device_and_named_script(tmp_path):
    with pytest.raises(ValidationError):
        _request(tmp_path, MobileConnectorType.FRIDA)

    request = _request(
        tmp_path,
        MobileConnectorType.FRIDA,
        profile=MobileAnalysisProfile.DYNAMIC,
        isolated_runtime_reference="emulator-snapshot-01",
        android_device_reference="emulator-5554",
        approved_script_id="tls-observation-01",
    )
    plan = build_mobile_connector_plan(request)

    assert plan.requires_approval is True
    assert plan.requires_isolation is True
    assert "arbitrary-script" in plan.forbidden_operations
    assert "run-approved-script:tls-observation-01" in plan.operations


def test_apkid_and_mobsf_reports_normalize_to_candidates(tmp_path):
    apkid = tmp_path / "apkid.json"
    apkid.write_text(json.dumps({"files": [{"packer": ["example-packer"]}]}))
    mobsf = tmp_path / "mobsf.json"
    mobsf.write_text(
        json.dumps(
            {
                "manifest_analysis": [
                    {
                        "rule": "cleartext_traffic",
                        "title": "Cleartext traffic is enabled",
                        "severity": "high",
                    }
                ]
            }
        )
    )

    apkid_findings = parse_apkid_json(apkid, artifact_sha256="c" * 64)
    mobsf_findings = parse_mobsf_json(mobsf, artifact_sha256="c" * 64)

    assert apkid_findings[0].tool_ids == ("apkid",)
    assert mobsf_findings[0].tool_ids == ("mobsf",)
    assert mobsf_findings[0].confidence == "candidate"
