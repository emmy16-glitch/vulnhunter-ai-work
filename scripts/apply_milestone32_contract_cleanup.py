from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected block missing from {relative}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        "tests/unit/test_web_app.py",
        '''            "/findings/",
            "/machine-oracle/",
            "/approvals/",
''',
        '''            "/findings/",
            "/approvals/",
''',
    )
    replace_once(
        "tests/unit/test_web_app.py",
        '''            assert response.status_code == 200, url
            assert b"Traceback" not in response.content
        settings_page = client.get("/settings/")
''',
        '''            assert response.status_code == 200, url
            assert b"Traceback" not in response.content
        verification_redirect = client.get("/machine-oracle/")
        assert verification_redirect.status_code == 302
        assert verification_redirect["Location"].endswith("/scans/")
        settings_page = client.get("/settings/")
''',
    )
    replace_once(
        "vulnhunter/ai_routing/service.py",
        '''    if request.privacy_class in {PrivacyClass.SECRET, PrivacyClass.CUSTOMER_PRIVATE}:
        return _decision(request, AiRoute.HUMAN_ESCALATION, "human review is required")
''',
        '''    if request.privacy_class in {PrivacyClass.SECRET, PrivacyClass.CUSTOMER_PRIVATE}:
        route = AiRoute.DENIED if request.public_freshness_required else AiRoute.HUMAN_ESCALATION
        return _decision(request, route, "private evidence cannot use remote advisory routing")
''',
    )
    replace_once(
        "tests/unit/test_nuclei_activation_controls.py",
        '''    assert profiles["execution_enabled"] is False
    assert profiles["automatic_updates_enabled"] is False
    assert manifest.entries == ()
''',
        '''    assert profiles["execution_enabled"] is False
    assert profiles["automatic_updates_enabled"] is False
    assert len(manifest.entries) == 1
    entry = manifest.entries[0]
    assert entry.template_id == "vulnhunter-passive-security-headers"
    assert entry.enabled is True
    assert entry.risk_class.value == "passive"
    assert entry.reviewed_by == "vulnhunter-security-review"
''',
    )
    replace_once(
        "tests/unit/test_nuclei_execution_harness.py",
        '''def test_scanner_protocol_registers_nuclei_openvas_and_mobile_under_one_interface(tmp_path):
    harness, _ = _bundle(tmp_path)
    registry = ScannerAdapterRegistry(
        [
            NucleiScannerAdapter(harness),
            PlannedScannerAdapter(
                ScannerAdapterDescriptor(
                    adapter_id="openvas-planned-adapter",
                    scanner_kind=ScannerKind.OPENVAS,
                    status=ScannerAdapterStatus.PLANNED,
                    deployment_mode=ScannerDeploymentMode.DISABLED,
                )
            ),
            PlannedScannerAdapter(
                ScannerAdapterDescriptor(
                    adapter_id="mobile-analysis-planned-adapter",
                    scanner_kind=ScannerKind.MOBILE_ANALYSIS,
                    status=ScannerAdapterStatus.PLANNED,
                    deployment_mode=ScannerDeploymentMode.DISABLED,
                )
            ),
        ]
    )

    assert [item.scanner_kind for item in registry.descriptors()] == [
        ScannerKind.MOBILE_ANALYSIS,
        ScannerKind.NUCLEI,
        ScannerKind.OPENVAS,
    ]
''',
        '''def test_scanner_protocol_registers_nuclei_and_mobile_under_one_interface(tmp_path):
    harness, _ = _bundle(tmp_path)
    registry = ScannerAdapterRegistry(
        [
            NucleiScannerAdapter(harness),
            PlannedScannerAdapter(
                ScannerAdapterDescriptor(
                    adapter_id="mobile-analysis-planned-adapter",
                    scanner_kind=ScannerKind.MOBILE_ANALYSIS,
                    status=ScannerAdapterStatus.PLANNED,
                    deployment_mode=ScannerDeploymentMode.DISABLED,
                )
            ),
        ]
    )

    assert [item.scanner_kind for item in registry.descriptors()] == [
        ScannerKind.MOBILE_ANALYSIS,
        ScannerKind.NUCLEI,
    ]
''',
    )
    replace_once(
        "tests/unit/test_nuclei_execution_harness.py",
        '''    assert {record.version_pin.scanner_id for record in manifest.records} == {
        "nuclei",
        "openvas",
        "mobile_analysis",
    }
''',
        '''    assert {record.version_pin.scanner_id for record in manifest.records} == {
        "nuclei",
        "mobile_analysis",
    }
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '''                ScannerCandidateObservation(
                    observation_id=f"nuclei-{fingerprint}",
                    title=redact_text(title)[:500],
''',
        '''                ScannerCandidateObservation(
                    observation_id=f"nuclei-{fingerprint}",
                    scanner_id="nuclei",
                    title=redact_text(title)[:500],
''',
    )
    replace_once(
        "vulnhunter/web/templates/web/agent_run_detail.html",
        '''<section class="vh-inspector-section"><small>Machine Oracle</small>''',
        '''<section class="vh-inspector-section"><small>Verification</small>''',
    )


if __name__ == "__main__":
    main()
