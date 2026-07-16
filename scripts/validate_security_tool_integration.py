#!/usr/bin/env python3
"""Focused validation for the governed external-tool integration release."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run(*argv: str, env: dict[str, str] | None = None) -> None:
    command = [PYTHON, *argv]
    print("\n$", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False, env=env)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    run("-m", "compileall", "-q", "vulnhunter")
    if importlib.util.find_spec("pytest") is None:
        print("pytest is required for tool-integration validation.")
        return 1
    run(
        "-m",
        "pytest",
        "-q",
        "tests/unit/test_advanced_assessment.py",
        "tests/unit/test_security_tool_governance.py",
        "tests/unit/test_mobile_tool_governance.py",
        "tests/unit/test_security_tool_integration.py",
    )

    env = os.environ.copy()
    env.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")
    env.setdefault(
        "VULNHUNTER_WEB_SECRET_KEY",
        "validation-only-not-for-production-7f3f6e75bce44c1ebde1",
    )
    if importlib.util.find_spec("django") is not None:
        run("-m", "django", "check", env=env)
        run("-m", "django", "makemigrations", "--check", "--dry-run", env=env)

    tools_bin = (
        Path(
            os.environ.get(
                "VULNHUNTER_TOOLS_ROOT",
                "/mnt/vulnhunter-data/tools/vulnhunter-external",
            )
        ).expanduser()
        / "bin"
    )
    if tools_bin.is_dir():
        run("scripts/security_tool_status.py", "--require-standard")
    else:
        print(f"External tools directory not mounted here; runtime probes skipped: {tools_bin}")

    print("\nSecurity tool integration validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
