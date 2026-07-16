import json
import zipfile
from pathlib import Path

import pytest

from vulnhunter.mobile import MobileArtifactError, MobileArtifactIngestor
from vulnhunter.mobile.artifacts import copy_artifact_for_analysis


def _write_apk(path: Path, *, native: bool = False, traversal: bool = False) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"binary-manifest-placeholder")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"x" * 32)
        if native:
            archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"x" * 32)
        if traversal:
            archive.writestr("../escape.txt", b"unsafe")
    return path


def test_ingest_apk_is_content_addressed_and_detects_native_libraries(tmp_path):
    source = _write_apk(tmp_path / "demo.apk", native=True)
    ingestor = MobileArtifactIngestor(tmp_path / "store")

    record = ingestor.ingest_file(source)

    assert record.artifact_id.startswith("apk-")
    assert record.stored_path.is_file()
    assert record.stored_path.parent.name == record.sha256
    assert record.dex_entries == ("classes.dex",)
    assert record.native_abis == ("arm64-v8a",)
    metadata = json.loads((record.stored_path.parent / "metadata.json").read_text())
    assert metadata["sha256"] == record.sha256


def test_ingest_same_apk_is_idempotent(tmp_path):
    source = _write_apk(tmp_path / "demo.apk")
    ingestor = MobileArtifactIngestor(tmp_path / "store")

    first = ingestor.ingest_file(source)
    second = ingestor.ingest_file(source)

    assert second.artifact_id == first.artifact_id
    assert second.sha256 == first.sha256
    assert len(ingestor.list_records()) == 1


def test_duplicate_and_workspace_integrity_hashing_is_streamed(tmp_path, monkeypatch):
    source = _write_apk(tmp_path / "demo.apk")
    ingestor = MobileArtifactIngestor(tmp_path / "store")
    record = ingestor.ingest_file(source)

    def reject_unbounded_read(_path):
        raise AssertionError("Path.read_bytes must not be used for APK integrity hashing")

    monkeypatch.setattr(Path, "read_bytes", reject_unbounded_read)
    duplicate = ingestor.ingest_file(source)
    copied = copy_artifact_for_analysis(record, tmp_path / "workspace")

    assert duplicate.sha256 == record.sha256
    assert copied.is_file()


def test_ingest_rejects_archive_path_traversal(tmp_path):
    source = _write_apk(tmp_path / "unsafe.apk", traversal=True)
    ingestor = MobileArtifactIngestor(tmp_path / "store")

    with pytest.raises(MobileArtifactError, match="unsafe archive path"):
        ingestor.ingest_file(source)


def test_ingest_rejects_non_apk_archive_contract(tmp_path):
    source = tmp_path / "invalid.apk"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("readme.txt", b"not an apk")
    ingestor = MobileArtifactIngestor(tmp_path / "store")

    with pytest.raises(MobileArtifactError, match="AndroidManifest.xml"):
        ingestor.ingest_file(source)
