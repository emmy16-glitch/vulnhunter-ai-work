#!/usr/bin/env python3
"""Focused validation for the manual completion package.

The script intentionally avoids the complete historical test suite. It verifies
only the newly installed completion modules and Django configuration checks.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = (
    "tests/unit/test_taskgraph.py",
    "tests/unit/test_threat_detection.py",
    "tests/unit/test_repository_graph.py",
    "tests/unit/test_context_broker.py",
    "tests/unit/test_skill_import.py",
    "tests/unit/test_findings_lifecycle.py",
    "tests/unit/test_report_exports.py",
    "tests/unit/test_provider_runtime.py",
    "tests/unit/test_binary_analysis.py",
    "tests/unit/test_privileged_broker.py",
)


def run(command: list[str], *, env: dict[str, str] | None = None) -> int:
    printable = " ".join(command)
    print(f"\n$ {printable}", flush=True)
    completed = subprocess.run(command, cwd=ROOT, env=env, check=False)
    return completed.returncode


def main() -> int:
    python = sys.executable
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)

    if run([python, "-m", "compileall", "-q", "vulnhunter"], env=env):
        return 1

    if importlib.util.find_spec("pytest") is None:
        print("pytest is unavailable; compile validation passed, focused tests skipped.")
        return 2
    if run([python, "-m", "pytest", "-q", *TESTS], env=env):
        return 1

    try:
        import django  # noqa: F401
    except ImportError:
        print("Django is unavailable in this interpreter; web system check skipped.")
    else:
        django_env = env.copy()
        django_env.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")
        django_env.setdefault("VULNHUNTER_WEB_DEBUG", "1")
        if run([python, "-m", "django", "check"], env=django_env):
            return 1

    print("\nManual completion validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
