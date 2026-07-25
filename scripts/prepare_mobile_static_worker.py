#!/usr/bin/env python3
"""Discover verified APK tools and write an owner-private worker policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
YARA_ROOT = ROOT / "config" / "security_tools" / "mobile_yara"
YARA_MANIFEST = YARA_ROOT / "manifest.json"
PYTHON_TOOLS_ROOT = ROOT / ".codespaces" / "tools" / "mobile-python"


def _executable(name: str) -> str | None:
    located = shutil.which(name)
    if not located:
        return None
    return _fixed_executable(Path(located))


def _fixed_executable(path: Path) -> str | None:
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        return None
    return str(resolved)


def _regular(path: Path) -> str | None:
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    return str(resolved) if stat.S_ISREG(metadata.st_mode) else None


def _directory(path: Path) -> str | None:
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    return str(resolved) if resolved.is_dir() else None


def _module_available(python: str, name: str) -> bool:
    probe = (
        "import importlib.util,sys; "
        f"sys.exit(0 if importlib.util.find_spec({name!r}) is not None else 1)"
    )
    try:
        completed = subprocess.run(
            (python, "-I", "-c", probe),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _verified_yara_rules() -> str | None:
    try:
        payload = json.loads(YARA_MANIFEST.read_text(encoding="utf-8"))
        rules = payload["rules"]
    except (OSError, KeyError, TypeError, ValueError):
        return None
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        return None
    relative = str(rules[0].get("path") or "")
    expected = str(rules[0].get("sha256") or "")
    candidate = YARA_ROOT / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(YARA_ROOT.resolve(strict=True))
        content = resolved.read_bytes()
    except (OSError, ValueError):
        return None
    if hashlib.sha256(content).hexdigest() != expected:
        return None
    return _regular(resolved)


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

    dedicated_python = _fixed_executable(PYTHON_TOOLS_ROOT / "bin" / "python")
    python = dedicated_python or str(Path(sys.executable).resolve(strict=True))
    apkid = _fixed_executable(PYTHON_TOOLS_ROOT / "bin" / "apkid") or _executable("apkid")
    androguard_adapter = (
        _regular(ROOT / "scripts" / "mobile_androguard_adapter.py")
        if _module_available(python, "androguard")
        else None
    )
    yara_rules = _verified_yara_rules() if _module_available(python, "yara") else None
    yara_adapter = _regular(ROOT / "scripts" / "mobile_yara_adapter.py") if yara_rules else None
    ghidra = _executable("analyzeHeadless")
    tools: dict[str, str | None] = {
        "aapt2_executable": _executable("aapt2") or _executable("aapt"),
        "apksigner_executable": _executable("apksigner"),
        "apkid_executable": apkid,
        "apktool_executable": _executable("apktool"),
        "jadx_executable": _executable("jadx"),
        "python_executable": python,
        "androguard_adapter": androguard_adapter,
        "yara_adapter": yara_adapter,
        "yara_rules_file": yara_rules,
        "radare2_executable": _executable("rabin2"),
        "ghidra_headless_executable": ghidra,
        "ghidra_script_root": (
            _directory(ROOT / "config" / "security_tools" / "ghidra_scripts") if ghidra else None
        ),
    }
    operational = {
        "aapt2": tools["aapt2_executable"],
        "apksigner": tools["apksigner_executable"],
        "apkid": tools["apkid_executable"],
        "apktool": tools["apktool_executable"],
        "jadx": tools["jadx_executable"],
        "androguard": tools["androguard_adapter"],
        "yara": tools["yara_adapter"],
        "radare2": tools["radare2_executable"],
        "ghidra": tools["ghidra_headless_executable"],
    }
    enabled = any(operational.values())
    args.workspace.mkdir(parents=True, exist_ok=True)
    args.workspace.chmod(0o700)
    payload: dict[str, object] = {
        "schema_version": "1.1",
        "enabled": enabled,
        "worker_id": args.worker_id,
        "workspace_root": str(args.workspace.resolve(strict=True)),
        "timeout_seconds": 180,
        "heavy_timeout_seconds": 600,
        "maximum_output_bytes": 1_000_000,
        "maximum_generated_bytes": 3_000_000_000,
        "maximum_generated_file_bytes": 750_000_000,
        "maximum_memory_bytes": 8_000_000_000,
        "maximum_native_libraries": 24,
        "network_isolation": "process_policy",
        **tools,
    }
    _write_private_json(args.policy, payload)
    available = ", ".join(name for name, path in operational.items() if path)
    if enabled:
        print(f"Mobile worker policy enabled with verified adapters: {available}.")
    else:
        print("Mobile worker policy remains disabled; no fixed read-only tools were found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
