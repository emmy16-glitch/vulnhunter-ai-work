#!/usr/bin/env python3
"""Interrogate and register one exact disposable Android emulator runtime."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_DEVICE_REFERENCE = re.compile(r"^[A-Za-z0-9._:@-]{1,255}$")


def _executable(name: str) -> Path:
    located = shutil.which(name)
    if not located:
        raise RuntimeError(f"{name} is unavailable")
    resolved = Path(located).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"{name} is not an executable file")
    return resolved


def _run(command: tuple[str, ...], *, timeout: int = 30) -> str:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=timeout,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/nonexistent",
            "TMPDIR": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_PROXY": "*",
            "no_proxy": "*",
            "http_proxy": "",
            "https_proxy": "",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "PYTHONNOUSERSITE": "1",
        },
    )
    output = completed.stdout.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        raise RuntimeError(f"command failed with exit code {completed.returncode}: {output[:200]}")
    return output


def _private_json(path: Path, payload: dict[str, object]) -> None:
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
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--adb-serial", required=True)
    parser.add_argument("--frida-device-id", required=True)
    parser.add_argument("--expires-hours", type=int, default=8)
    args = parser.parse_args()

    if _RUNTIME_ID.fullmatch(args.runtime_id) is None:
        raise SystemExit("runtime ID must be a stable lowercase identifier")
    if _DEVICE_REFERENCE.fullmatch(args.adb_serial) is None:
        raise SystemExit("ADB serial is invalid")
    if _DEVICE_REFERENCE.fullmatch(args.frida_device_id) is None:
        raise SystemExit("Frida device ID is invalid")
    if not 1 <= args.expires_hours <= 24:
        raise SystemExit("runtime registration must expire within 1-24 hours")

    adb = _executable("adb")
    frida_cli = _executable("frida")
    python = Path(sys.executable).resolve(strict=True)
    adapter = (ROOT / "scripts" / "mobile_frida_inventory.py").resolve(strict=True)
    if adapter.is_symlink() or not adapter.is_file():
        raise SystemExit("fixed Frida inventory adapter is unavailable")

    prefix = (str(adb), "-s", args.adb_serial)
    if _run((*prefix, "get-state")) != "device":
        raise SystemExit("registered ADB device is not online")
    qemu = _run((*prefix, "shell", "getprop", "ro.boot.qemu"))
    if qemu != "1":
        raise SystemExit("registered Android device is not an emulator")
    fingerprint = _run((*prefix, "shell", "getprop", "ro.build.fingerprint"))
    api_level = int(_run((*prefix, "shell", "getprop", "ro.build.version.sdk")))
    abi = _run((*prefix, "shell", "getprop", "ro.product.cpu.abi"))
    frida_version = _run((str(frida_cli), "--version"))
    if re.fullmatch(r"\d+\.\d+\.\d+", frida_version) is None:
        raise SystemExit("Frida client version is invalid")

    now = datetime.now(UTC)
    payload = {
        "schema_version": "1.0",
        "enabled": True,
        "runtime_id": args.runtime_id,
        "adb_executable": str(adb),
        "python_executable": str(python),
        "frida_executable": str(frida_cli),
        "frida_inventory_adapter": str(adapter),
        "adb_serial": args.adb_serial,
        "frida_device_id": args.frida_device_id,
        "expected_fingerprint": fingerprint,
        "expected_api_level": api_level,
        "expected_abi": abi,
        "expected_frida_version": frida_version,
        "expires_at": (now + timedelta(hours=args.expires_hours)).isoformat(),
        "disposable": True,
        "emulator_required": True,
        "maximum_command_seconds": 120,
        "maximum_session_seconds": 900,
        "maximum_output_bytes": 1_000_000,
        "maximum_memory_bytes": 2_000_000_000,
    }
    policy = args.policy.expanduser().absolute()
    _private_json(policy, payload)
    print(f"Registered disposable runtime: {args.runtime_id}")
    print(f"ADB serial: {args.adb_serial}")
    print(f"Fingerprint: {fingerprint}")
    print(f"API/ABI: {api_level}/{abi}")
    print(f"Frida: {frida_version}")
    print(f"Expires: {payload['expires_at']}")
    print(f"Policy: {policy}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
