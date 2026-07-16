import zipfile

import pytest

from vulnhunter.security_tools.adapters import ToolAdapterError, build_command_plan
from vulnhunter.security_tools.catalog import default_catalog
from vulnhunter.security_tools.models import (
    SecurityToolRequest,
    ToolProfile,
    ToolTargetKind,
)


def _apk(tmp_path):
    path = tmp_path / "demo.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
    return path


def _request(tmp_path, tool_id, **updates):
    apk = _apk(tmp_path)
    values = {
        "request_id": "mobile-request-01",
        "action_manifest_sha256": "a" * 64,
        "tool_id": tool_id,
        "profile": ToolProfile.MOBILE_STATIC,
        "operation": "static",
        "target": str(apk.resolve()),
        "target_kind": ToolTargetKind.APK_FILE,
        "timeout_seconds": 60,
        "maximum_output_bytes": 100_000,
        "output_directory": tmp_path / "evidence",
    }
    values.update(updates)
    return SecurityToolRequest(**values)


def test_catalog_contains_android_security_toolchain():
    ids = {item.tool_id for item in default_catalog().list()}
    assert {
        "apksigner",
        "aapt2",
        "apktool",
        "jadx",
        "apkid",
        "yara",
        "androguard",
        "mobsf",
        "radare2",
        "ghidra",
        "adb",
        "frida",
    } <= ids


def test_jadx_plan_is_shell_free_and_uses_governed_output_directory(tmp_path):
    request = _request(tmp_path, "jadx")
    plan = build_command_plan(
        request,
        executable="/opt/jadx/bin/jadx",
        catalog=default_catalog(),
    )

    assert plan.argv[0] == "/opt/jadx/bin/jadx"
    assert "--output-dir" in plan.argv
    assert plan.argv[-1].endswith("demo.apk")
    assert plan.output_files[0].name.endswith("-jadx")
    assert plan.requires_isolation is False


def test_apksigner_plan_captures_signature_evidence(tmp_path):
    request = _request(tmp_path, "apksigner")
    plan = build_command_plan(
        request,
        executable="/usr/bin/apksigner",
        catalog=default_catalog(),
    )

    assert plan.argv[1:4] == ("verify", "--verbose", "--print-certs")
    assert plan.stdout_file is not None
    assert plan.stdout_file.name.endswith(".signature.txt")


def test_dynamic_mobsf_requires_connector_and_cannot_use_direct_adapter(tmp_path):
    request = _request(
        tmp_path,
        "mobsf",
        profile=ToolProfile.MOBILE_DYNAMIC,
    )
    with pytest.raises(ToolAdapterError, match="dedicated connector"):
        build_command_plan(
            request,
            executable="/opt/mobsf/runserver.sh",
            catalog=default_catalog(),
        )


def test_apk_tool_rejects_network_target_kind(tmp_path):
    request = _request(
        tmp_path,
        "jadx",
        target="https://example.test/demo.apk",
        target_kind=ToolTargetKind.NETWORK,
    )
    with pytest.raises(ToolAdapterError, match="does not accept target kind"):
        build_command_plan(
            request,
            executable="/opt/jadx/bin/jadx",
            catalog=default_catalog(),
        )
