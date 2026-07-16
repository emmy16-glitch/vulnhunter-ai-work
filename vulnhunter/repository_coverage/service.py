"""Deterministic repository coverage inventory builder."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from vulnhunter.actions.models import sha256_json
from vulnhunter.repository_coverage.models import (
    CoverageExclusion,
    CoverageInventory,
    CoverageItem,
    CoverageState,
)

_LANGUAGE_SUFFIXES = {
    ".py": "python",
    ".md": "markdown",
    ".json": "json",
    ".html": "html",
    ".css": "css",
    ".js": "javascript",
}
_GENERATED_DIRECTORY_COMPONENTS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "artifacts",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
}


def build_inventory(
    root: Path, *, exclusions: tuple[CoverageExclusion, ...] = ()
) -> CoverageInventory:
    resolved = root.expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("repository coverage root must be a directory")

    explicit_exclusions = {item.path: item.reason for item in exclusions}
    recorded_exclusions = dict(explicit_exclusions)
    items: list[CoverageItem] = []

    for path, relative in _walk_repository(resolved, recorded_exclusions):
        try:
            digest = _hash_stable_regular_file(path, root=resolved)
        except (OSError, ValueError) as exc:
            recorded_exclusions[relative] = _safe_read_failure_reason(exc)
            continue
        reason = explicit_exclusions.get(relative)
        state = CoverageState.EXCLUDED if reason is not None else CoverageState.ELIGIBLE
        items.append(
            CoverageItem(
                path=relative,
                sha256=digest,
                language=_LANGUAGE_SUFFIXES.get(path.suffix, "other"),
                component=relative.split("/", 1)[0],
                state=state,
                exclusion_reason=reason,
            )
        )

    normalized_exclusions = tuple(
        CoverageExclusion(path=path, reason=reason)
        for path, reason in sorted(recorded_exclusions.items())
    )
    sorted_items = tuple(sorted(items, key=lambda item: item.path))
    root_digest = sha256_json(
        {
            "items": [item.model_dump(mode="json") for item in sorted_items],
            "exclusions": [item.model_dump(mode="json") for item in normalized_exclusions],
        }
    )
    return CoverageInventory(
        root_sha256=root_digest,
        items=sorted_items,
        exclusions=normalized_exclusions,
    )


def _walk_repository(
    root: Path,
    recorded_exclusions: dict[str, str],
):
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            relative = directory.relative_to(root).as_posix()
            if relative != ".":
                recorded_exclusions[relative] = _safe_read_failure_reason(exc)
            continue
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                if entry.is_symlink():
                    recorded_exclusions[relative] = "symbolic links are not inventoried"
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in _GENERATED_DIRECTORY_COMPONENTS:
                        recorded_exclusions[relative] = "generated directory excluded by policy"
                    else:
                        child_directories.append(path)
                    continue
                if entry.is_file(follow_symlinks=False):
                    yield path, relative
            except OSError as exc:
                recorded_exclusions[relative] = _safe_read_failure_reason(exc)
        pending.extend(reversed(child_directories))


def _hash_stable_regular_file(path: Path, *, root: Path) -> str:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise ValueError("symbolic link rejected")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("non-regular file rejected")

    canonical = path.resolve(strict=True)
    try:
        canonical.relative_to(root)
    except ValueError as exc:
        raise ValueError("canonical file path escapes repository root") from exc
    if canonical != path:
        raise ValueError("symbolic link rejected")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            raise ValueError("non-regular file rejected")
        if (before.st_dev, before.st_ino, before.st_ctime_ns) != (
            opened_before.st_dev,
            opened_before.st_ino,
            opened_before.st_ctime_ns,
        ):
            raise ValueError("file changed before inventory read")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    after = path.lstat()
    stable_identity = (
        opened_after.st_dev,
        opened_after.st_ino,
        opened_after.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_ctime_ns,
    )
    stable_content = (
        (
            opened_before.st_size,
            opened_before.st_mtime_ns,
            opened_before.st_ctime_ns,
        )
        == (
            opened_after.st_size,
            opened_after.st_mtime_ns,
            opened_after.st_ctime_ns,
        )
        == (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
    )
    if not stable_identity or not stable_content or stat.S_ISLNK(after.st_mode):
        raise ValueError("file changed during inventory read")
    return digest.hexdigest()


def _safe_read_failure_reason(error: OSError | ValueError) -> str:
    if isinstance(error, FileNotFoundError):
        return "file disappeared during inventory"
    if isinstance(error, PermissionError):
        return "file could not be read under current permissions"
    if "symbolic link" in str(error):
        return "symbolic links are not inventoried"
    if "escapes repository" in str(error):
        return "canonical path is outside repository root"
    if "changed" in str(error):
        return "file changed during inventory"
    return "file could not be safely inventoried"
