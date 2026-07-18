#!/usr/bin/env python3
"""Validate scanner protocol, version/feed pins, and documented compatibility."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnhunter.security_tools.scanner_protocol import (
    ScannerAdapterStatus,
    ScannerCompatibilityManifest,
    render_compatibility_matrix,
)

START = "<!-- scanner-compatibility:start -->"
END = "<!-- scanner-compatibility:end -->"


def _replace_matrix(document: str, matrix: str) -> str:
    if document.count(START) != 1 or document.count(END) != 1:
        raise ValueError("compatibility document must contain one matrix marker pair")
    before, remainder = document.split(START, 1)
    _, after = remainder.split(END, 1)
    return f"{before}{START}\n\n{matrix.rstrip()}\n\n{END}{after}"


def validate(repository_root: Path, *, write: bool = False) -> str:
    root = repository_root.expanduser().resolve(strict=True)
    manifest_path = root / "config/security_tools/scanner_compatibility.json"
    runtime_path = root / "config/security_tools/runtime.json"
    document_path = root / "docs/product/SCANNER_COMPATIBILITY.md"

    manifest = ScannerCompatibilityManifest.load(manifest_path)
    manifest.verify_repository_manifests(root)
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))

    if runtime.get("execution_enabled") is not False:
        raise ValueError("global security-tool execution must remain disabled")
    worker = runtime.get("scanner_worker", {})
    if worker.get("execution_enabled") is not False:
        raise ValueError("scanner worker execution must remain disabled")
    if worker.get("transport_enabled") is not False:
        raise ValueError("scanner worker transport must remain disabled")
    nuclei = runtime.get("nuclei", {})
    if nuclei.get("real_runner_enabled") is not False:
        raise ValueError("the default Nuclei runner must remain disabled")

    nuclei_record = manifest.get("nuclei")
    if nuclei_record.descriptor.status is not ScannerAdapterStatus.HARNESS_ONLY:
        raise ValueError("Nuclei compatibility status must remain harness_only")
    mobile_record = manifest.get("mobile_analysis")
    if mobile_record.descriptor.status is not ScannerAdapterStatus.PLANNED:
        raise ValueError("mobile analysis must remain planned")

    matrix = render_compatibility_matrix(manifest)
    document = document_path.read_text(encoding="utf-8")
    expected = _replace_matrix(document, matrix)
    if write:
        document_path.write_text(expected, encoding="utf-8")
    elif document != expected:
        raise ValueError(
            "scanner compatibility documentation is stale; run "
            "python scripts/validate_scanner_compatibility.py --write"
        )

    return manifest.fingerprint()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Update the documented matrix.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fingerprint = validate(root, write=args.write)
    print(f"Scanner compatibility manifest: {fingerprint}")
    print("Default scanner execution enabled: false")


if __name__ == "__main__":
    main()
