#!/usr/bin/env python3
"""Read-only readiness report for the governed standard VulnHunter toolchain."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.security_tools.catalog import default_catalog

STANDARD_TOOL_IDS = (
    "nmap",
    "httpx",
    "nuclei",
    "ffuf",
    "testssl",
    "trivy",
    "bearer",
    "bandit",
    "detect-secrets",
    "gitleaks",
    "syft",
    "grype",
    "osv-scanner",
    "capa",
)


def enable_tools_path() -> Path:
    root = Path(
        os.environ.get(
            "VULNHUNTER_TOOLS_ROOT",
            "/mnt/vulnhunter-data/tools/vulnhunter-external",
        )
    ).expanduser()
    binary_directory = root / "bin"
    if binary_directory.is_dir():
        os.environ["PATH"] = f"{binary_directory}:{os.environ.get('PATH', '')}"
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-standard", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("var/readiness/security-tool-integration.json"),
    )
    args = parser.parse_args()

    tools_root = enable_tools_path()
    catalog = default_catalog()
    availability = catalog.detect_many(STANDARD_TOOL_IDS)

    rows = {item.tool_id: item.model_dump(mode="json") for item in availability}
    ready = sorted(item.tool_id for item in availability if item.usable)
    not_ready = sorted(item.tool_id for item in availability if not item.usable)
    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "tools_root": str(tools_root),
        "execution_enabled": False,
        "ready": ready,
        "not_ready": not_ready,
        "tools": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"\nSaved readiness report to {args.output}")
    if args.require_standard and not_ready:
        print("Required standard tools are not ready: " + ", ".join(not_ready))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
