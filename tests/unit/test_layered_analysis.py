from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.mobile.layered_analysis import LayerStatus, analyze_package
from vulnhunter.mobile.models import MobileArtifactRecord


def _fake_elf() -> bytes:
    data = bytearray(256)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    struct.pack_into("<H", data, 16, 3)
    struct.pack_into("<H", data, 18, 183)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 1)
    struct.pack_into("<I", data, 64, 0x6474E551)
    struct.pack_into("<I", data, 68, 6)
    return bytes(data) + b"Java_com_example_Native_startPlay https://native.av380.net"


def _fake_dex() -> bytes:
    return (
        b"dex\n035\x00"
        + b"\x00" * 128
        + b"Lcom/macrovideo/v380pro/HSMediaLibrary;"
        + b"Lcom/google/android/gms/ads/AdView;"
        + b"HSMediaLibrary.cipherJsonData addJavascriptInterface "
        + b"https://api.av380.net/device"
    )


def test_layered_analysis_reconstructs_static_architecture(tmp_path: Path) -> None:
    package = tmp_path / "V380.apk"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("AndroidManifest.xml", b'<manifest package="com.macrovideo.v380pro"/>')
        archive.writestr("classes.dex", _fake_dex())
        archive.writestr("lib/arm64-v8a/libhsMediaLibrary.so", _fake_elf())
        archive.writestr("assets/config.json", b'{"endpoint":"https://config.av380.net"}')

    report = analyze_package(package)

    assert report.file_type == "apk_or_zip"
    assert report.artifact_sha256
    assert report.sha1
    assert report.md5
    assert report.manifest["parse_status"] == "text_xml"
    assert len(report.dex_inventory) == 1
    assert report.dex_inventory[0].magic_valid is True
    assert report.dex_inventory[0].first_party_namespaces == ("com.macrovideo.v380pro",)
    assert len(report.native_inventory) == 1
    assert report.native_inventory[0].architecture == "ARM64"
    assert any(item.endpoint == "https://api.av380.net/device" for item in report.network_endpoints)
    assert any(item.endpoint == "https://config.av380.net" for item in report.network_endpoints)
    assert any(edge.relation == "contains_native_library" for edge in report.architecture_edges)
    assert any(item["category"] == "network_static" for item in report.observations)
    assert any(item.status == LayerStatus.BLOCKED for item in report.completeness.layers)
    assert report.next_actions


def test_layered_analysis_rejects_digest_mismatch(tmp_path: Path) -> None:
    package = tmp_path / "sample.apk"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("classes.dex", _fake_dex())

    try:
        record = MobileArtifactRecord(
            artifact_id="apk-test-record",
            original_filename="sample.apk",
            stored_path=package,
            sha256="0" * 64,
            size_bytes=package.stat().st_size,
            archive_entry_count=2,
            total_uncompressed_bytes=10,
            manifest_entry="AndroidManifest.xml",
            dex_entries=("classes.dex",),
        )
    except ValidationError as exc:
        raise AssertionError("test fixture should validate") from exc

    try:
        analyze_package(package, artifact=record)
    except Exception as exc:
        assert "digest" in str(exc)
    else:
        raise AssertionError("digest mismatch must fail closed")
