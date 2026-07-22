#!/usr/bin/env python3
"""Validate scanner protocol, controlled activation, version pins, and documentation."""

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
    profiles_path = root / "config/security_tools/nuclei_profiles.json"
    worker_policy_path = root / "config/security_tools/nuclei_worker_pilot.json"
    document_path = root / "docs/product/SCANNER_COMPATIBILITY.md"

    manifest = ScannerCompatibilityManifest.load(manifest_path)
    manifest.verify_repository_manifests(root)
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    profiles = json.loads(profiles_path.read_text(encoding="utf-8"))
    worker_policy = json.loads(worker_policy_path.read_text(encoding="utf-8"))

    required_enabled = {
        "global security-tool execution": runtime.get("execution_enabled"),
        "active assessment": runtime.get("active_assessment_enabled"),
        "validation": runtime.get("validation_enabled"),
        "connectors": runtime.get("connectors_enabled"),
        "Nuclei": runtime.get("nuclei", {}).get("enabled"),
        "Nuclei real runner": runtime.get("nuclei", {}).get("real_runner_enabled"),
        "scanner worker execution": runtime.get("scanner_worker", {}).get("execution_enabled"),
        "scanner worker transport": runtime.get("scanner_worker", {}).get("transport_enabled"),
        "Nuclei profiles": profiles.get("execution_enabled"),
        "private-lab worker policy": worker_policy.get("enabled"),
    }
    disabled = sorted(name for name, enabled in required_enabled.items() if enabled is not True)
    if disabled:
        raise ValueError(f"controlled activation is incomplete: {disabled}")

    nuclei = runtime.get("nuclei", {})
    worker = runtime.get("scanner_worker", {})
    prohibited_enabled = {
        "privileged broker": runtime.get("privileged_broker_enabled"),
        "network listener": worker.get("network_listener_enabled"),
        "automatic updates": nuclei.get("automatic_updates_enabled"),
        "cloud upload": nuclei.get("cloud_upload_enabled"),
        "public OAST": nuclei.get("public_oast_enabled"),
        "unsigned templates": nuclei.get("unsigned_templates_allowed"),
        "code templates": nuclei.get("code_templates_enabled"),
        "file templates": nuclei.get("file_templates_enabled"),
        "self-contained templates": nuclei.get("self_contained_templates_enabled"),
        "generated templates": nuclei.get("ai_template_generation_enabled"),
    }
    unsafe = sorted(name for name, enabled in prohibited_enabled.items() if enabled is not False)
    if unsafe:
        raise ValueError(f"unsafe scanner capabilities must remain disabled: {unsafe}")
    if worker.get("maximum_concurrency") != 1:
        raise ValueError("the activated scanner worker must retain concurrency one")
    if worker_policy.get("private_targets_only") is not True:
        raise ValueError("the activated worker must remain private-target-only")
    if worker_policy.get("maximum_rate_limit") != 1:
        raise ValueError("the activated worker must retain rate limit one")
    if worker_policy.get("maximum_concurrency") != 1:
        raise ValueError("the activated worker policy must retain concurrency one")

    nuclei_record = manifest.get("nuclei")
    if nuclei_record.descriptor.status not in {
        ScannerAdapterStatus.HARNESS_ONLY,
        ScannerAdapterStatus.PILOT_READY,
    }:
        raise ValueError("Nuclei compatibility status is not approved for the controlled pilot")
    engine_pin = nuclei_record.version_pin.engine_version
    feed = nuclei_record.version_pin.feed
    if engine_pin is None or feed is None or feed.release is None:
        raise ValueError("Nuclei compatibility requires explicit engine and template pins")
    if nuclei.get("engine_version") != engine_pin:
        raise ValueError("Nuclei runtime engine version differs from compatibility policy")
    if profiles.get("engine_pin") != engine_pin:
        raise ValueError("Nuclei profile engine version differs from compatibility policy")
    if nuclei.get("templates_version") != feed.release:
        raise ValueError("Nuclei runtime template version differs from compatibility policy")
    if profiles.get("templates_pin") != feed.release:
        raise ValueError("Nuclei profile template version differs from compatibility policy")

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
    print("Controlled private-lab scanner execution enabled: true")


if __name__ == "__main__":
    main()
