"""Atomic and integrity-checked benchmark manifest persistence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.benchmark.models import BenchmarkManifest
from vulnhunter.exceptions import BenchmarkManifestError

_MAXIMUM_MANIFEST_BYTES = 2 * 1024 * 1024


def _canonical_payload(manifest: BenchmarkManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def manifest_sha256(manifest: BenchmarkManifest) -> str:
    """Hash canonical manifest content for model provenance."""
    return hashlib.sha256(_canonical_payload(manifest)).hexdigest()


def save_manifest(manifest: BenchmarkManifest, output_path: Path) -> None:
    """Atomically store a private benchmark manifest with an integrity digest."""
    resolved = output_path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolved.with_suffix(resolved.suffix + ".tmp")

    payload = manifest.model_dump(mode="json")
    envelope = {
        "manifest": payload,
        "sha256": manifest_sha256(manifest),
    }
    encoded = json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")

    if len(encoded) > _MAXIMUM_MANIFEST_BYTES:
        raise BenchmarkManifestError("Benchmark manifest exceeds the 2 MiB limit.")

    try:
        with temporary.open("wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, resolved)
    finally:
        temporary.unlink(missing_ok=True)


def load_manifest(path: Path) -> BenchmarkManifest:
    """Load and verify one bounded benchmark manifest."""
    resolved = path.expanduser().resolve()

    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise BenchmarkManifestError(f"Unable to read benchmark manifest: {exc}") from exc

    if size > _MAXIMUM_MANIFEST_BYTES:
        raise BenchmarkManifestError("Benchmark manifest exceeds the 2 MiB limit.")

    try:
        envelope = json.loads(resolved.read_text(encoding="utf-8"))
        manifest = BenchmarkManifest.model_validate(envelope["manifest"])
        stored_digest = str(envelope["sha256"])
    except (
        OSError,
        UnicodeError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        ValidationError,
    ) as exc:
        raise BenchmarkManifestError("Benchmark manifest is malformed or incompatible.") from exc

    actual_digest = manifest_sha256(manifest)
    if not hmac.compare_digest(stored_digest, actual_digest):
        raise BenchmarkManifestError("Benchmark manifest integrity validation failed.")

    return manifest
