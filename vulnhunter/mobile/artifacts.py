"""Content-addressed APK ingestion with archive safety checks."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from vulnhunter.mobile.models import MobileArtifactRecord


class MobileArtifactError(ValueError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class MobileArtifactIngestor:
    def __init__(
        self,
        root: Path,
        *,
        maximum_apk_bytes: int = 1_000_000_000,
        maximum_entries: int = 50_000,
        maximum_uncompressed_bytes: int = 4_000_000_000,
        maximum_compression_ratio: int = 500,
    ) -> None:
        self.root = root.expanduser().resolve()
        self.maximum_apk_bytes = maximum_apk_bytes
        self.maximum_entries = maximum_entries
        self.maximum_uncompressed_bytes = maximum_uncompressed_bytes
        self.maximum_compression_ratio = maximum_compression_ratio
        self.root.mkdir(parents=True, exist_ok=True)

    def ingest_file(
        self,
        source: Path,
        *,
        original_filename: str | None = None,
    ) -> MobileArtifactRecord:
        path = source.expanduser()
        if not path.is_absolute() or path.is_symlink():
            raise MobileArtifactError("APK source must be a non-symlink absolute path")
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise MobileArtifactError("APK source must be a regular file")
        name = original_filename or resolved.name
        with resolved.open("rb") as handle:
            return self.ingest_chunks(name, iter(lambda: handle.read(1024 * 1024), b""))

    def ingest_chunks(self, filename: str, chunks: Iterable[bytes]) -> MobileArtifactRecord:
        safe_name = Path(filename).name
        if not safe_name.lower().endswith(".apk"):
            raise MobileArtifactError("uploaded file must use the .apk extension")
        incoming = self.root / ".incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix="apk-", suffix=".part", dir=incoming)
        temporary = Path(temporary_name)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise MobileArtifactError("APK upload chunks must be bytes")
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > self.maximum_apk_bytes:
                        raise MobileArtifactError("APK exceeds the configured size limit")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            if size == 0:
                raise MobileArtifactError("APK upload is empty")

            archive = self._inspect_archive(temporary)
            sha256 = digest.hexdigest()
            artifact_id = f"apk-{sha256[:24]}"
            destination_directory = self.root / sha256
            destination_directory.mkdir(parents=True, exist_ok=True)
            destination = destination_directory / "original.apk"
            if destination.exists():
                if _sha256_file(destination) != sha256:
                    raise MobileArtifactError(
                        "existing content-addressed APK failed integrity check"
                    )
                temporary.unlink(missing_ok=True)
            else:
                os.chmod(temporary, 0o600)
                os.replace(temporary, destination)

            record = MobileArtifactRecord(
                artifact_id=artifact_id,
                original_filename=safe_name,
                stored_path=destination,
                sha256=sha256,
                size_bytes=size,
                archive_entry_count=archive["entry_count"],
                total_uncompressed_bytes=archive["uncompressed_bytes"],
                manifest_entry=archive["manifest_entry"],
                dex_entries=archive["dex_entries"],
                native_libraries=archive["native_libraries"],
                native_abis=archive["native_abis"],
                ingested_at=datetime.now(UTC),
            )
            self._write_metadata(destination_directory / "metadata.json", record)
            return record
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def list_records(self) -> tuple[MobileArtifactRecord, ...]:
        records: list[MobileArtifactRecord] = []
        for metadata in sorted(self.root.glob("[0-9a-f]*/metadata.json")):
            try:
                records.append(
                    MobileArtifactRecord.model_validate_json(metadata.read_text(encoding="utf-8"))
                )
            except (OSError, ValueError):
                continue
        return tuple(sorted(records, key=lambda item: item.ingested_at, reverse=True))

    def _inspect_archive(self, path: Path) -> dict[str, object]:
        if not zipfile.is_zipfile(path):
            raise MobileArtifactError("APK is not a valid ZIP-compatible archive")
        entry_count = 0
        uncompressed = 0
        manifest_entry: str | None = None
        dex_entries: list[str] = []
        native_libraries: list[str] = []
        native_abis: set[str] = set()
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                entry_count += 1
                if entry_count > self.maximum_entries:
                    raise MobileArtifactError("APK contains too many archive entries")
                self._validate_entry_name(info.filename)
                if self._is_symlink(info):
                    raise MobileArtifactError("APK archive contains a symbolic-link entry")
                uncompressed += info.file_size
                if uncompressed > self.maximum_uncompressed_bytes:
                    raise MobileArtifactError("APK uncompressed size exceeds the configured limit")
                if info.compress_size == 0:
                    if info.file_size > 0:
                        raise MobileArtifactError(
                            "APK contains an unsafe zero-size compression entry"
                        )
                elif info.file_size / info.compress_size > self.maximum_compression_ratio:
                    raise MobileArtifactError("APK contains an unsafe compression-ratio entry")
                if info.filename == "AndroidManifest.xml":
                    manifest_entry = info.filename
                if info.filename.startswith("classes") and info.filename.endswith(".dex"):
                    dex_entries.append(info.filename)
                parts = PurePosixPath(info.filename).parts
                if len(parts) == 3 and parts[0] == "lib" and info.filename.endswith(".so"):
                    native_libraries.append(info.filename)
                    native_abis.add(parts[1])
        if manifest_entry is None:
            raise MobileArtifactError("APK does not contain AndroidManifest.xml")
        if not dex_entries:
            raise MobileArtifactError("APK does not contain any classes*.dex entry")
        return {
            "entry_count": entry_count,
            "uncompressed_bytes": uncompressed,
            "manifest_entry": manifest_entry,
            "dex_entries": tuple(sorted(dex_entries)),
            "native_libraries": tuple(sorted(native_libraries)),
            "native_abis": tuple(sorted(native_abis)),
        }

    @staticmethod
    def _validate_entry_name(name: str) -> None:
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\x00" in name:
            raise MobileArtifactError("APK contains an unsafe archive path")

    @staticmethod
    def _is_symlink(info: zipfile.ZipInfo) -> bool:
        mode = (info.external_attr >> 16) & 0o170000
        return mode == 0o120000

    @staticmethod
    def _write_metadata(path: Path, record: MobileArtifactRecord) -> None:
        data = json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
        temporary = path.with_suffix(".json.part")
        temporary.write_text(data, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)


def copy_artifact_for_analysis(record: MobileArtifactRecord, destination: Path) -> Path:
    """Copy an ingested APK into an isolated analysis workspace without altering it."""

    workspace = destination.expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    output = workspace / f"{record.artifact_id}.apk"
    if output.exists():
        if _sha256_file(output) != record.sha256:
            raise MobileArtifactError("existing workspace APK failed integrity validation")
        return output
    shutil.copy2(record.stored_path, output)
    os.chmod(output, 0o400)
    if _sha256_file(output) != record.sha256:
        output.unlink(missing_ok=True)
        raise MobileArtifactError("workspace APK copy failed integrity validation")
    return output
