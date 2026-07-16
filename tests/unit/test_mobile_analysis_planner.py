from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.mobile import (
    MobileAnalysisPlanner,
    MobileAnalysisProfile,
    MobileAnalysisRequest,
    MobileArtifactRecord,
)
from vulnhunter.security_tools.catalog import default_catalog


def _artifact(tmp_path: Path, *, native: bool = False) -> MobileArtifactRecord:
    apk = tmp_path / "original.apk"
    apk.write_bytes(b"placeholder")
    return MobileArtifactRecord(
        artifact_id="apk-aaaaaaaaaaaaaaaaaaaaaaaa",
        original_filename="demo.apk",
        stored_path=apk,
        sha256="a" * 64,
        size_bytes=11,
        archive_entry_count=2,
        total_uncompressed_bytes=20,
        manifest_entry="AndroidManifest.xml",
        dex_entries=("classes.dex",),
        native_libraries=("lib/arm64-v8a/libdemo.so",) if native else (),
        native_abis=("arm64-v8a",) if native else (),
    )


def _request(tmp_path: Path, profile: MobileAnalysisProfile, **updates):
    values = {
        "analysis_id": "mobile-analysis-01",
        "campaign_id": "campaign-01",
        "run_id": "run-01",
        "requested_by": "operator-01",
        "artifact_id": "apk-aaaaaaaaaaaaaaaaaaaaaaaa",
        "artifact_sha256": "a" * 64,
        "artifact_path": tmp_path / "original.apk",
        "profile": profile,
        "authorization_references": ("authorization-01",),
    }
    values.update(updates)
    return MobileAnalysisRequest(**values)


def test_static_native_profile_selects_apk_and_native_tools(tmp_path):
    artifact = _artifact(tmp_path, native=True)
    request = _request(tmp_path, MobileAnalysisProfile.STATIC_AND_NATIVE)

    manifests, graph = MobileAnalysisPlanner(default_catalog()).build(request, artifact)

    assert [item.tool_id for item in manifests] == [
        "apksigner",
        "aapt2",
        "apkid",
        "apktool",
        "jadx",
        "androguard",
        "yara",
        "radare2",
        "ghidra",
    ]
    assert graph.nodes[-1].dependencies == (graph.nodes[-2].node_id,)
    assert manifests[-1].approval_required is True


def test_dynamic_profile_requires_isolated_runtime_and_device(tmp_path):
    _artifact(tmp_path)
    with pytest.raises(ValidationError, match="isolated runtime"):
        _request(tmp_path, MobileAnalysisProfile.DYNAMIC)


def test_dynamic_profile_builds_approval_bound_runtime_tools(tmp_path):
    artifact = _artifact(tmp_path)
    request = _request(
        tmp_path,
        MobileAnalysisProfile.DYNAMIC,
        isolated_runtime_reference="emulator-snapshot-01",
        android_device_reference="emulator-5554",
    )

    manifests, _ = MobileAnalysisPlanner(default_catalog()).build(request, artifact)

    assert [item.tool_id for item in manifests] == ["mobsf", "adb", "frida"]
    assert all(item.approval_required for item in manifests)
    assert all(item.role_id == "mobile-dynamic-analysis-specialist" for item in manifests)
