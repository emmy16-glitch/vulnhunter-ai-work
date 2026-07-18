#!/usr/bin/env python3
"""Read-only readiness report for optional VulnHunter external tools."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.security_tools.catalog import run_ordered_readiness_probes

TOOLS: dict[str, tuple[str, ...]] = {
    "nmap": ("nmap", "--version"),
    "httpx": ("httpx", "--version"),
    "nuclei": ("nuclei", "-version"),
    "ffuf": ("ffuf", "-V"),
    "bearer": ("bearer", "--version"),
    "bandit": ("bandit", "--version"),
    "detect-secrets": ("detect-secrets", "--version"),
    "gitleaks": ("gitleaks", "version"),
    "trivy": ("trivy", "--version"),
    "syft": ("syft", "version"),
    "grype": ("grype", "version"),
    "osv-scanner": ("osv-scanner", "--version"),
    "jadx": ("jadx", "--version"),
    "apktool": ("apktool", "--version"),
    "aapt": ("aapt", "version"),
    "aapt2": ("aapt2", "version"),
    "adb": ("adb", "version"),
    "yara": ("yara", "--version"),
    "capa": ("capa", "--version"),
    "rabin2": ("rabin2", "-v"),
    "graphify": ("graphify", "--version"),
    "docker": ("docker", "--version"),
    "podman": ("podman", "--version"),
}


def probe(argv: tuple[str, ...]) -> dict[str, object]:
    executable = shutil.which(argv[0])
    if executable is None:
        return {"installed": False, "executable": None, "version": None}
    try:
        completed = subprocess.run(
            (executable, *argv[1:]),
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={
                key: os.environ[key]
                for key in (
                    "PATH",
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "SSL_CERT_FILE",
                    "SSL_CERT_DIR",
                )
                if key in os.environ
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "installed": True,
            "executable": executable,
            "version": None,
            "error": str(exc),
        }
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return {
        "installed": True,
        "executable": executable,
        "version": text[0][:240] if text else None,
        "returncode": completed.returncode,
    }


def main() -> int:
    results = run_ordered_readiness_probes(
        TOOLS.items(),
        lambda item: (item[0], probe(item[1])),
    )
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "activation_performed": False,
        "tools": dict(results),
    }
    destination = Path("var/readiness/dependency-readiness.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"\nSaved read-only readiness report to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
