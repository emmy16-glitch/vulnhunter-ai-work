from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from tempfile import mkstemp
from typing import Any

from django.conf import settings

from vulnhunter.web.backup_recovery import (
    BackupRecoveryError,
    configured_backup_sources,
    verify_backup_bundle,
)


@dataclass(frozen=True, slots=True)
class RestoreExecutionResult:
    bundle_digest: str
    databases_restored: int
    rollback_directory: Path

    def as_payload(self) -> dict[str, Any]:
        return {
            "status": "restored",
            "bundle_digest": self.bundle_digest,
            "databases_restored": self.databases_restored,
            "rollback_retained": True,
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup_bundle_digest(bundle: Path) -> str:
    manifest = bundle.expanduser() / "manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise BackupRecoveryError("Backup manifest is unavailable for digest binding.")
    return _sha256(manifest)


def _load_json(path: Path, error: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BackupRecoveryError(error)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupRecoveryError(error) from exc
    if not isinstance(payload, dict):
        raise BackupRecoveryError(error)
    return payload


def _owner_only(path: Path) -> bool:
    try:
        mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
    except OSError:
        return False
    return mode & (stat.S_IRWXG | stat.S_IRWXO) == 0


def _validate_maintenance_marker(marker: Path, bundle_digest: str) -> None:
    payload = _load_json(marker.expanduser(), "Maintenance marker is unavailable or invalid.")
    if not _owner_only(marker):
        raise BackupRecoveryError("Maintenance marker permissions are not owner-only.")
    valid = (
        payload.get("application") == "vulnhunter"
        and payload.get("maintenance") is True
        and payload.get("database_mode") == "sqlite"
        and payload.get("bundle_digest") == bundle_digest
    )
    if not valid:
        raise BackupRecoveryError("Maintenance marker does not authorize this exact restore.")


def _sqlite_integrity(path: Path) -> bool:
    try:
        uri = f"{path.resolve().as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            return connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    except (OSError, sqlite3.Error):
        return False


def _snapshot_sqlite(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise BackupRecoveryError("A configured live SQLite database is unavailable.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"{source.resolve().as_uri()}?mode=ro"
    try:
        with sqlite3.connect(source_uri, uri=True) as source_connection:
            with sqlite3.connect(destination) as destination_connection:
                source_connection.backup(destination_connection)
    except sqlite3.Error as exc:
        raise BackupRecoveryError("Unable to create the pre-restore rollback snapshot.") from exc
    destination.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if not _sqlite_integrity(destination):
        raise BackupRecoveryError("Pre-restore rollback snapshot failed integrity checks.")


def _atomic_replace(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = mkstemp(
        prefix=f".{destination.name}.restore.",
        dir=destination.parent,
    )
    os.close(file_descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary, follow_symlinks=False)
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
        if not _sqlite_integrity(temporary):
            raise BackupRecoveryError("A staged SQLite restore file failed integrity checks.")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _load_sqlite_entries(bundle: Path) -> dict[str, tuple[Path, str]]:
    manifest = _load_json(
        bundle / "manifest.json",
        "Backup manifest is unavailable or invalid.",
    )
    if manifest.get("database_mode") != "sqlite":
        raise BackupRecoveryError("In-process restore execution supports SQLite bundles only.")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise BackupRecoveryError("Backup manifest entries are invalid.")
    result: dict[str, tuple[Path, str]] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict) or raw_entry.get("kind") != "sqlite":
            continue
        logical_name = str(raw_entry.get("logical_name", ""))
        relative_path = str(raw_entry.get("relative_path", ""))
        expected_sha = str(raw_entry.get("sha256", ""))
        candidate = bundle.joinpath(*Path(relative_path).parts)
        result[logical_name] = (candidate, expected_sha)
    return result


def _restore_rollback(
    rollback_directory: Path,
    live_databases: dict[str, Path],
    replaced: list[str],
) -> None:
    failures: list[str] = []
    for logical_name in reversed(replaced):
        rollback = rollback_directory / f"{logical_name}.sqlite3"
        try:
            _atomic_replace(rollback, live_databases[logical_name])
        except (BackupRecoveryError, OSError):
            failures.append(logical_name)
    if failures:
        raise BackupRecoveryError(
            "Restore failed and automatic rollback could not recover every database."
        )


def execute_verified_sqlite_restore(
    bundle: Path,
    *,
    expected_bundle_digest: str,
    maintenance_marker: Path,
    rollback_directory: Path,
) -> RestoreExecutionResult:
    bundle = bundle.expanduser()
    rollback_directory = rollback_directory.expanduser()
    verification = verify_backup_bundle(bundle)
    if not verification.valid:
        raise BackupRecoveryError("Restore execution is blocked by backup verification.")
    if settings.DATABASE_ENGINE != "sqlite":
        raise BackupRecoveryError("In-process restore execution requires SQLite deployment mode.")
    actual_digest = backup_bundle_digest(bundle)
    if expected_bundle_digest != actual_digest:
        raise BackupRecoveryError("Requested bundle digest does not match the verified backup.")
    _validate_maintenance_marker(maintenance_marker, actual_digest)
    if rollback_directory.exists() or rollback_directory.is_symlink():
        raise BackupRecoveryError("Rollback directory must not already exist.")

    database_sources, _ = configured_backup_sources()
    live_databases = {
        source.logical_name: source.source.expanduser()
        for source in database_sources
        if source.kind == "sqlite"
    }
    bundle_entries = _load_sqlite_entries(bundle)
    if set(bundle_entries) != set(live_databases):
        raise BackupRecoveryError(
            "Backup database inventory does not match the configured SQLite deployment."
        )
    for candidate, expected_sha in bundle_entries.values():
        if candidate.is_symlink() or not candidate.is_file() or _sha256(candidate) != expected_sha:
            raise BackupRecoveryError("A restore database no longer matches its verified manifest.")

    rollback_directory.mkdir(parents=True, mode=stat.S_IRWXU)
    rollback_directory.chmod(stat.S_IRWXU)
    try:
        for logical_name, live_path in live_databases.items():
            _snapshot_sqlite(
                live_path,
                rollback_directory / f"{logical_name}.sqlite3",
            )
    except (BackupRecoveryError, OSError):
        shutil.rmtree(rollback_directory, ignore_errors=True)
        raise

    replaced: list[str] = []
    try:
        for logical_name in sorted(live_databases):
            source, _ = bundle_entries[logical_name]
            _atomic_replace(source, live_databases[logical_name])
            replaced.append(logical_name)
        for logical_name, live_path in live_databases.items():
            source, expected_sha = bundle_entries[logical_name]
            if not _sqlite_integrity(live_path):
                raise BackupRecoveryError("Post-restore SQLite integrity verification failed.")
            if _sha256(live_path) != expected_sha or _sha256(source) != expected_sha:
                raise BackupRecoveryError("Post-restore database digest verification failed.")
    except (BackupRecoveryError, OSError) as exc:
        _restore_rollback(rollback_directory, live_databases, replaced)
        raise BackupRecoveryError("Restore failed and live databases were rolled back.") from exc

    return RestoreExecutionResult(
        bundle_digest=actual_digest,
        databases_restored=len(live_databases),
        rollback_directory=rollback_directory,
    )
