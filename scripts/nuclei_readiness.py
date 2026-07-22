#!/usr/bin/env python3
"""Verify the pinned Nuclei binary and reviewed local template set without scanning."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

EXPECTED_ENGINE = "v3.8.0"
EXPECTED_TEMPLATES = "v10.4.5"
_VERSION_TOKEN = re.compile(r"(?<![0-9A-Za-z.+-])v?(\d+\.\d+\.\d+)(?![0-9A-Za-z.+-])")


def _version_matches(expected: str, output: str) -> bool:
    normalized = expected.removeprefix("v")
    return normalized in _VERSION_TOKEN.findall(output)


def _probe(executable: str, *arguments: str) -> dict[str, object]:
    try:
        completed = subprocess.run(
            (executable, *arguments),
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env={
                "PATH": str(Path(executable).parent),
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "return_code": None, "summary": str(exc)[:500]}
    text = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
    return {
        "ok": completed.returncode == 0,
        "return_code": completed.returncode,
        "summary": text[:2000],
    }


def verify_template_manifest(manifest_path: Path, template_root: Path) -> dict[str, object]:
    result: dict[str, object] = {
        "ok": False,
        "release_matches": False,
        "all_digests_match": False,
        "enabled_template_count": 0,
        "manifest": str(manifest_path),
        "template_root": str(template_root),
    }
    try:
        raw = manifest_path.read_bytes()
        payload = json.loads(raw)
        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise ValueError("template manifest entries must be a list")
        release = payload.get("template_release")
        enabled = [
            entry
            for entry in entries
            if isinstance(entry, dict) and entry.get("enabled") is True
        ]
        if not enabled:
            raise ValueError("template manifest has no enabled reviewed templates")
        mismatches: list[str] = []
        for entry in enabled:
            relative = entry.get("relative_path")
            expected_sha = entry.get("sha256")
            entry_release = entry.get("template_release")
            if not isinstance(relative, str) or not isinstance(expected_sha, str):
                mismatches.append(str(entry.get("template_id") or "invalid-entry"))
                continue
            resolved_root = template_root.resolve(strict=True)
            lexical_candidate = template_root / relative
            if lexical_candidate.is_symlink():
                mismatches.append(relative)
                continue
            candidate = lexical_candidate.resolve(strict=True)
            candidate.relative_to(resolved_root)
            if not candidate.is_file():
                mismatches.append(relative)
                continue
            actual_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if actual_sha != expected_sha or entry_release != EXPECTED_TEMPLATES:
                mismatches.append(relative)
        result.update(
            {
                "release": release,
                "release_matches": release == EXPECTED_TEMPLATES,
                "all_digests_match": not mismatches,
                "enabled_template_count": len(enabled),
                "mismatches": mismatches,
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        result["ok"] = bool(result["release_matches"] and result["all_digests_match"])
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)[:500]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".local/nuclei-readiness/readiness.json"),
    )
    parser.add_argument("--executable", type=Path, default=None)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("config/security_tools/nuclei_template_manifest.json"),
    )
    parser.add_argument(
        "--template-root",
        type=Path,
        default=Path("config/security_tools/pilot_templates"),
    )
    parser.add_argument("--execution-enabled", action="store_true")
    parser.add_argument("--require-ready", action="store_true")
    arguments = parser.parse_args()

    executable = (
        str(arguments.executable.expanduser().resolve())
        if arguments.executable is not None
        else shutil.which("nuclei")
    )
    installed = bool(executable and Path(executable).is_file())
    report: dict[str, object] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "expected_engine": EXPECTED_ENGINE,
        "expected_templates": EXPECTED_TEMPLATES,
        "installed": installed,
        "executable": executable,
        "execution_enabled": bool(arguments.execution_enabled),
        "scan_performed": False,
        "update_performed": False,
    }

    engine: dict[str, object] = {"ok": False, "summary": "nuclei executable was not found"}
    if installed and executable:
        engine = _probe(executable, "-version")
    report["engine_probe"] = engine
    report["engine_pin_matches"] = _version_matches(
        EXPECTED_ENGINE, str(engine.get("summary", ""))
    )

    template_report = verify_template_manifest(
        arguments.manifest.expanduser().resolve(),
        arguments.template_root.expanduser().resolve(),
    )
    report["template_verification"] = template_report
    report["templates_pin_matches"] = bool(template_report.get("ok"))
    report["ready"] = bool(
        installed
        and engine.get("ok")
        and report["engine_pin_matches"]
        and report["templates_pin_matches"]
        and report["execution_enabled"]
    )
    if report["ready"]:
        report["reason"] = (
            "Pinned Nuclei, reviewed template digests and the private-lab execution policy "
            "were verified."
        )
    elif not installed:
        report["reason"] = "The pinned Nuclei executable is not installed."
    elif not report["engine_pin_matches"]:
        report["reason"] = "The installed Nuclei engine does not match v3.8.0."
    elif not report["templates_pin_matches"]:
        report["reason"] = "The reviewed passive template release or digest did not verify."
    else:
        report["reason"] = "The private-lab execution policy is not enabled."

    output = arguments.output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Nuclei readiness report: {output.resolve()}")
    print(f"Ready: {report['ready']}")
    print("No scan, update, upload, or public target operation was performed.")
    if arguments.require_ready and not report["ready"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
