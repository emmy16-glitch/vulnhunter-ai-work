#!/usr/bin/env python3
"""Run a fixed reviewed YARA ruleset and emit bounded JSON match receipts."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path

import yara

_MAX_FILES = 20_000
_MAX_FILE_BYTES = 100 * 1024 * 1024
_MAX_TOTAL_BYTES = 1_000 * 1024 * 1024
_MAX_MATCHES = 250
_MAX_STRING_RECEIPTS = 40


def _candidates(roots: tuple[Path, ...]) -> Iterable[tuple[Path, Path]]:
    seen: set[Path] = set()
    for root in roots:
        values = (root,) if root.is_file() else sorted(root.rglob("*"))
        for candidate in values:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            yield root, resolved


def _string_receipts(match: yara.Match) -> list[dict[str, object]]:
    receipts: list[dict[str, object]] = []
    for string_match in match.strings:
        identifier = str(getattr(string_match, "identifier", ""))
        instances = getattr(string_match, "instances", ())
        for instance in instances:
            receipts.append(
                {
                    "identifier": identifier,
                    "offset": int(getattr(instance, "offset", 0)),
                    "length": int(getattr(instance, "matched_length", 0)),
                }
            )
            if len(receipts) >= _MAX_STRING_RECEIPTS:
                return receipts
    return receipts


def _reference(root: Path, candidate: Path) -> str:
    try:
        relative = candidate.relative_to(root) if root.is_dir() else Path(candidate.name)
    except ValueError:
        relative = Path(candidate.name)
    return f"{root.name}/{relative.as_posix()}"


def scan(rules_path: Path, roots: tuple[Path, ...]) -> dict[str, object]:
    rules = yara.compile(filepath=str(rules_path))
    matches: list[dict[str, object]] = []
    scanned_files = 0
    scanned_bytes = 0
    truncated = False
    for root, candidate in _candidates(roots):
        if scanned_files >= _MAX_FILES or scanned_bytes >= _MAX_TOTAL_BYTES:
            truncated = True
            break
        try:
            size = candidate.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_BYTES or scanned_bytes + size > _MAX_TOTAL_BYTES:
            truncated = True
            continue
        try:
            file_matches = rules.match(filepath=str(candidate), timeout=20)
        except (OSError, yara.Error, yara.TimeoutError):
            continue
        scanned_files += 1
        scanned_bytes += size
        for match in file_matches:
            matches.append(
                {
                    "rule": str(match.rule),
                    "namespace": str(match.namespace),
                    "tags": sorted(str(tag) for tag in match.tags),
                    "meta": {str(key): value for key, value in match.meta.items()},
                    "file": _reference(root, candidate),
                    "strings": _string_receipts(match),
                }
            )
            if len(matches) >= _MAX_MATCHES:
                truncated = True
                break
        if len(matches) >= _MAX_MATCHES:
            break
    return {
        "schema_version": "1.0",
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
        "matches": matches,
        "truncated": truncated,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True, action="append")
    args = parser.parse_args()
    rules_path = args.rules.expanduser().resolve(strict=True)
    roots = tuple(target.expanduser().resolve(strict=True) for target in args.target)
    if not rules_path.is_file():
        raise SystemExit("YARA rules path is not a regular file")
    print(json.dumps(scan(rules_path, roots), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
