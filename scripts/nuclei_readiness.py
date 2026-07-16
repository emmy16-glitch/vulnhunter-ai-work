#!/usr/bin/env python3
"""Read-only Nuclei engine/template readiness report.

This script never installs, updates, or runs a scan. It only executes local
version commands with a bounded timeout and writes a JSON readiness record.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

EXPECTED_ENGINE = "v3.11.0"
EXPECTED_TEMPLATES = "v10.4.5"


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
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "return_code": None, "summary": str(exc)[:500]}

    text = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
    return {
        "ok": completed.returncode == 0,
        "return_code": completed.returncode,
        "summary": text[:2000],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/nuclei-readiness/readiness.json"),
    )
    parser.add_argument("--require-ready", action="store_true")
    arguments = parser.parse_args()

    executable = shutil.which("nuclei")
    report: dict[str, object] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "expected_engine": EXPECTED_ENGINE,
        "expected_templates": EXPECTED_TEMPLATES,
        "installed": executable is not None,
        "executable": executable,
        "execution_enabled": False,
        "scan_performed": False,
        "update_performed": False,
    }

    if executable is None:
        report["ready"] = False
        report["reason"] = "nuclei executable was not found on PATH"
    else:
        engine = _probe(executable, "-version")
        templates = _probe(executable, "-templates-version")
        report["engine_probe"] = engine
        report["templates_probe"] = templates
        engine_text = str(engine.get("summary", ""))
        template_text = str(templates.get("summary", ""))
        report["engine_pin_matches"] = EXPECTED_ENGINE.lstrip("v") in engine_text
        report["templates_pin_matches"] = EXPECTED_TEMPLATES.lstrip("v") in template_text
        report["ready"] = bool(
            engine["ok"]
            and templates["ok"]
            and report["engine_pin_matches"]
            and report["templates_pin_matches"]
        )

    output = arguments.output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Nuclei readiness report: {output.resolve()}")
    print(f"Ready: {report['ready']}")
    print("No scan, install, update, upload, or network target operation was performed.")

    if arguments.require_ready and not report["ready"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
