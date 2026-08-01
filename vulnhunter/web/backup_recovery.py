from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import mkdtemp
from typing import Any

from django.conf import settings

_BACKUP_SCHEMA_VERSION = "1.0"
_MANIFEST_NAME = "manifest.json"
_DATA_ROOT = "data"


class BackupRecoveryError(RuntimeError):
    """Raised when a backup cannot be created or trusted safely."""


@dataclass(frozen=True, slots=True)
class BackupSource:
    logical_name: str
    kind: str
    source: Path


@dataclass(frozen=True, slots=True)
class BackupEntry:
    logical_name: str
    kind: str
    relative_path: str
    sha256: str
    size: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "logical_name": self.logical_name,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class BackupVerificationReport:
    checks: tuple[tuple[str, bool], ...]
    entries: int
    sqlite_databases: int
    external_database_dump: bool

    @property
    def valid(self) -> bool:
        return all(passed for _, passed in self.checks)

    def as_payload(self) -> dict[str, Any]:
        return {
            "status": "valid" if self.valid else "invalid",
            "checks": {name: "ok" if passed else "failed" for name, passed in self.checks},
            "entries": self.entries,
            "sqlite_databases": self.sqlite_databases,
            "external_database_dump": self.external_database_dump,
        }


@dataclass(frozen=True, slots=True)
class RestorePlan:
    verification: BackupVerificationReport
    actions: tuple[tuple[str, str], ...]

    @property
    def ready(self) -> bool:
        return self.verification.valid

    def as_payload(self) -> dict[str, Any]:
        return {
            "status": "ready" if self.ready else "blocked",
            "verification": self.verification.as_payload(),
            "actions": [
                {"logical_name": logical_name, "action": action}
                for logical_name, action in self.actions
            ],
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative_path(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise BackupRecoveryError("Backup manifest contains an unsafe relative path.")
    return relative


def _safe_logical_name(value: str) -> str:
    if not value or not value.replace("_", "").isalnum():
        raise BackupRecoveryError("Backup source has an unsafe logical name.")
    return value


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)
    path.chmod(stat.S_IRWXU)


def _secure_file(path: Path) -> None:
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _copy_regular_file(source: Path, destination: Path) -> BackupEntry:
    if source.is_symlink() or not source.is_file():
        raise BackupRecoveryError("Backup sources must be regular files and cannot be symlinks.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination, follow_symlinks=False)
    _secure_file(destination)
    return BackupEntry(
        logical_name="",
        kind="file",
        relative_path=destination.as_posix(),
        sha256=_sha256(destination),
        size=destination.stat().st_size,
    )


def _snapshot_sqlite(source: Path, destination: Path, logical_name: str) -> BackupEntry:
    if source.is_symlink() or not source.is_file():
        raise BackupRecoveryError(f"Required SQLite source is unavailable: {logical_name}.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"file:{source.resolve().as_posix()}?mode=ro"
    try:
        with sqlite3.connect(source_uri, uri=True) as source_connection:
            with sqlite3.connect(destination) as destination_connection:
                source_connection.backup(destination_connection)
                result = destination_connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as exc:
        raise BackupRecoveryError(f"SQLite snapshot failed for {logical_name}.") from exc
    if result != ("ok",):
        raise BackupRecoveryError(f"SQLite snapshot integrity failed for {logical_name}.")
    _secure_file(destination)
    return BackupEntry(
        logical_name=logical_name,
        kind="sqlite",
        relative_path=destination.as_posix(),
        sha256=_sha256(destination),
        size=destination.stat().st_size,
    )


def _directory_entries(source: BackupSource, staging: Path) -> list[BackupEntry]:
    if not source.source.exists():
        return []
    if source.source.is_symlink() or not source.source.is_dir():
        raise BackupRecoveryError(f"Backup directory is invalid: {source.logical_name}.")
    entries: list[BackupEntry] = []
    for candidate in sorted(source.source.rglob("*")):
        if candidate.is_symlink():
            raise BackupRecoveryError(
                f"Backup directory contains a symlink: {source.logical_name}."
            )
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise BackupRecoveryError(
                f"Backup directory contains a non-regular file: {source.logical_name}."
            )
        relative = candidate.relative_to(source.source)
        destination_relative = (
            PurePosixPath(_DATA_ROOT)
            / "files"
            / source.logical_name
            / PurePosixPath(relative.as_posix())
        )
        destination = staging.joinpath(*destination_relative.parts)
        copied = _copy_regular_file(candidate, destination)
        entries.append(
            BackupEntry(
                logical_name=source.logical_name,
                kind="file",
                relative_path=destination_relative.as_posix(),
                sha256=copied.sha256,
                size=copied.size,
            )
        )
    return entries


def configured_backup_sources() -> tuple[tuple[BackupSource, ...], tuple[BackupSource, ...]]:
    databases = (
        BackupSource(
            "authorization_database",
            "sqlite",
            Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE).expanduser(),
        ),
        BackupSource(
            "governance_database",
            "sqlite",
            Path(settings.VULNHUNTER_GOVERNANCE_DATABASE).expanduser(),
        ),
        BackupSource(
            "agent_database",
            "sqlite",
            Path(settings.VULNHUNTER_AGENT_DATABASE).expanduser(),
        ),
        BackupSource(
            "approval_database",
            "sqlite",
            Path(settings.VULNHUNTER_APPROVAL_DATABASE).expanduser(),
        ),
        BackupSource(
            "adversary_lab_database",
            "sqlite",
            Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE).expanduser(),
        ),
    )
    if settings.DATABASE_ENGINE == "sqlite":
        databases = (
            BackupSource(
                "web_database",
                "sqlite",
                Path(settings.DATABASES["default"]["NAME"]).expanduser(),
            ),
            *databases,
        )
    directories = (
        BackupSource(
            "agent_activity",
            "directory",
            Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT).expanduser(),
        ),
        BackupSource(
            "security_evidence",
            "directory",
            Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT).expanduser(),
        ),
        BackupSource(
            "verification",
            "directory",
            Path(settings.VULNHUNTER_VERIFICATION_ROOT).expanduser(),
        ),
        BackupSource(
            "task_graphs",
            "directory",
            Path(settings.VULNHUNTER_TASK_GRAPH_ROOT).expanduser(),
        ),
        BackupSource(
            "adversary_lab_workspaces",
            "directory",
            Path(settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT).expanduser(),
        ),
        BackupSource(
            "adversary_lab_evidence",
            "directory",
            Path(settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT).expanduser(),
        ),
        BackupSource(
            "mobile_artifacts",
            "directory",
            Path(settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT).expanduser(),
        ),
        BackupSource(
            "nuclei_executions",
            "directory",
            Path(settings.VULNHUNTER_NUCLEI_EXECUTION_ROOT).expanduser(),
        ),
        BackupSource("web_media", "directory", Path(settings.MEDIA_ROOT).expanduser()),
    )
    return databases, directories


def _copy_postgresql_dump(source: Path, staging: Path) -> BackupEntry:
    logical_name = "web_database"
    relative = PurePosixPath(_DATA_ROOT) / "databases" / "web_database.pg_dump"
    destination = staging.joinpath(*relative.parts)
    copied = _copy_regular_file(source, destination)
    return BackupEntry(
        logical_name=logical_name,
        kind="postgresql_dump",
        relative_path=relative.as_posix(),
        sha256=copied.sha256,
        size=copied.size,
    )


def create_backup_bundle(destination: Path, *, postgresql_dump: Path | None = None) -> dict[str, Any]:
    destination = destination.expanduser()
    if destination.exists() or destination.is_symlink():
        raise BackupRecoveryError("Backup destination must not already exist.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    temporary.chmod(stat.S_IRWXU)
    try:
        database_sources, directory_sources = configured_backup_sources()
        entries: list[BackupEntry] = []
        for source in database_sources:
            logical_name = _safe_logical_name(source.logical_name)
            relative = PurePosixPath(_DATA_ROOT) / "databases" / f"{logical_name}.sqlite3"
            snapshot = _snapshot_sqlite(
                source.source,
                temporary.joinpath(*relative.parts),
                logical_name,
            )
            entries.append(
                BackupEntry(
                    logical_name=snapshot.logical_name,
                    kind=snapshot.kind,
                    relative_path=relative.as_posix(),
                    sha256=snapshot.sha256,
                    size=snapshot.size,
                )
            )
        if settings.DATABASE_ENGINE == "postgresql":
            if postgresql_dump is None:
                raise BackupRecoveryError(
                    "PostgreSQL deployments require an externally created pg_dump artifact."
                )
            entries.append(_copy_postgresql_dump(postgresql_dump.expanduser(), temporary))
        elif postgresql_dump is not None:
            raise BackupRecoveryError(
                "A PostgreSQL dump can only be supplied when PostgreSQL is configured."
            )
        for source in directory_sources:
            _safe_logical_name(source.logical_name)
            entries.extend(_directory_entries(source, temporary))
        entries.sort(key=lambda item: (item.logical_name, item.relative_path))
        manifest = {
            "schema_version": _BACKUP_SCHEMA_VERSION,
            "application": "vulnhunter",
            "created_at": datetime.now(UTC).isoformat(),
            "database_mode": settings.DATABASE_ENGINE,
            "entries": [entry.as_payload() for entry in entries],
        }
        manifest_path = temporary / _MANIFEST_NAME
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _secure_file(manifest_path)
        os.replace(temporary, destination)
        return {
            "status": "created",
            "database_mode": settings.DATABASE_ENGINE,
            "entries": len(entries),
            "sqlite_databases": sum(entry.kind == "sqlite" for entry in entries),
            "external_database_dump": any(
                entry.kind == "postgresql_dump" for entry in entries
            ),
        }
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _load_manifest(bundle: Path) -> dict[str, Any]:
    manifest_path = bundle / _MANIFEST_NAME
    if bundle.is_symlink() or not bundle.is_dir() or manifest_path.is_symlink():
        raise BackupRecoveryError("Backup bundle is not a trusted directory.")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupRecoveryError("Backup manifest is unreadable.") from exc
    if not isinstance(payload, dict):
        raise BackupRecoveryError("Backup manifest must be an object.")
    return payload


def _sqlite_integrity(path: Path) -> bool:
    try:
        with sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True) as connection:
            return connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    except sqlite3.Error:
        return False


def verify_backup_bundle(bundle: Path) -> BackupVerificationReport:
    bundle = bundle.expanduser()
    checks: list[tuple[str, bool]] = []
    try:
        manifest = _load_manifest(bundle)
    except BackupRecoveryError:
        return BackupVerificationReport(
            checks=(("manifest_readable", False),),
            entries=0,
            sqlite_databases=0,
            external_database_dump=False,
        )
    entries_payload = manifest.get("entries")
    schema_valid = manifest.get("schema_version") == _BACKUP_SCHEMA_VERSION
    application_valid = manifest.get("application") == "vulnhunter"
    entries_valid = isinstance(entries_payload, list)
    checks.extend(
        (
            ("manifest_readable", True),
            ("schema_supported", schema_valid),
            ("application_matches", application_valid),
            ("entries_well_formed", entries_valid),
        )
    )
    if not entries_valid:
        return BackupVerificationReport(
            checks=tuple(checks),
            entries=0,
            sqlite_databases=0,
            external_database_dump=False,
        )
    seen_paths: set[str] = set()
    expected_files = {_MANIFEST_NAME}
    hashes_valid = True
    sizes_valid = True
    paths_valid = True
    sqlite_valid = True
    sqlite_count = 0
    external_dump = False
    for raw_entry in entries_payload:
        if not isinstance(raw_entry, dict):
            paths_valid = False
            continue
        try:
            relative = _safe_relative_path(str(raw_entry.get("relative_path", "")))
            logical_name = _safe_logical_name(str(raw_entry.get("logical_name", "")))
        except BackupRecoveryError:
            paths_valid = False
            continue
        kind = str(raw_entry.get("kind", ""))
        if kind not in {"file", "sqlite", "postgresql_dump"} or not logical_name:
            paths_valid = False
            continue
        relative_text = relative.as_posix()
        if relative_text in seen_paths:
            paths_valid = False
            continue
        seen_paths.add(relative_text)
        expected_files.add(relative_text)
        candidate = bundle.joinpath(*relative.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(bundle.resolve(strict=True))
        except (OSError, ValueError):
            paths_valid = False
            continue
        if candidate.is_symlink() or not candidate.is_file():
            paths_valid = False
            continue
        try:
            expected_size = int(raw_entry.get("size", -1))
        except (TypeError, ValueError):
            expected_size = -1
        expected_sha = str(raw_entry.get("sha256", ""))
        sizes_valid = sizes_valid and candidate.stat().st_size == expected_size
        hashes_valid = hashes_valid and _sha256(candidate) == expected_sha
        if kind == "sqlite":
            sqlite_count += 1
            sqlite_valid = sqlite_valid and _sqlite_integrity(candidate)
        if kind == "postgresql_dump":
            external_dump = True
    actual_files: set[str] = set()
    for candidate in bundle.rglob("*"):
        if candidate.is_symlink() or (not candidate.is_dir() and not candidate.is_file()):
            paths_valid = False
            continue
        if candidate.is_file():
            actual_files.add(candidate.relative_to(bundle).as_posix())
    checks.extend(
        (
            ("paths_safe", paths_valid),
            ("files_complete", actual_files == expected_files),
            ("sizes_match", sizes_valid),
            ("hashes_match", hashes_valid),
            ("sqlite_integrity", sqlite_valid),
        )
    )
    return BackupVerificationReport(
        checks=tuple(checks),
        entries=len(entries_payload),
        sqlite_databases=sqlite_count,
        external_database_dump=external_dump,
    )


def plan_restore(bundle: Path) -> RestorePlan:
    verification = verify_backup_bundle(bundle)
    if not verification.valid:
        return RestorePlan(verification=verification, actions=())
    manifest = _load_manifest(bundle.expanduser())
    actions: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_entry in manifest["entries"]:
        logical_name = str(raw_entry["logical_name"])
        if logical_name in seen:
            continue
        seen.add(logical_name)
        kind = str(raw_entry["kind"])
        action = "external_database_restore" if kind == "postgresql_dump" else "replace_after_stop"
        actions.append((logical_name, action))
    actions.sort()
    return RestorePlan(verification=verification, actions=tuple(actions))
