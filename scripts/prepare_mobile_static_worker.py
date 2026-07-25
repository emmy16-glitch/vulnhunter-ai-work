#!/usr/bin/env python3
"""Discover verified read-only APK tools and write an owner-private worker policy."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path


def _executable(name: str) -> str | None:
    located = shutil.which(name)
    if not located:
        return None
    try:
        resolved = Path(located).resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        return None
    return str(resolved)


def _write_private_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--worker-id", default="codespaces-mobile-static-worker")
    args = parser.parse_args()

    tools = {
        "aapt2_executable": _executable("aapt2"),
        "apksigner_executable": _executable("apksigner"),
        "apkid_executable": _executable("apkid"),
        "apktool_executable": _executable("apktool"),
    }
    enabled = any(tools.values())
    args.workspace.mkdir(parents=True, exist_ok=True)
    args.workspace.chmod(0o700)
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "enabled": enabled,
        "worker_id": args.worker_id,
        "workspace_root": str(args.workspace.resolve(strict=True)),
        "timeout_seconds": 120,
        "maximum_output_bytes": 750_000,
        "networkless_runtime_required": True,
        **tools,
    }
    _write_private_json(args.policy, payload)
    available = ", ".join(name.removesuffix("_executable") for name, path in tools.items() if path)
    if enabled:
        print(f"Mobile static worker policy enabled with: {available}.")
    else:
        print("Mobile static worker policy remains disabled; no fixed read-only tools were found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
