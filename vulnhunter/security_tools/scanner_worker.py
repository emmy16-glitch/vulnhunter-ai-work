"""Disabled scanner-worker entry point for isolated container deployment.

Milestone 31 ships only the process boundary.  The worker validates the central
compatibility manifest, reports that execution is disabled, and exits without
loading a scanner binary, opening a socket, or accepting a job.
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnhunter.security_tools.scanner_protocol import ScannerCompatibilityManifest


def disabled_worker_status(repository_root: Path) -> dict[str, object]:
    manifest_path = repository_root / "config/security_tools/scanner_compatibility.json"
    manifest = ScannerCompatibilityManifest.load(manifest_path)
    manifest.verify_repository_manifests(repository_root)
    return {
        "protocol_version": manifest.schema_version,
        "compatibility_manifest_sha256": manifest.fingerprint(),
        "worker_state": "blocked_execution_disabled",
        "execution_enabled": False,
        "network_listener_started": False,
        "scanner_process_started": False,
        "adapters": [
            {
                "adapter_id": record.descriptor.adapter_id,
                "scanner": record.descriptor.scanner_kind.value,
                "status": record.descriptor.status.value,
            }
            for record in manifest.records
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(disabled_worker_status(root), sort_keys=True))
    raise SystemExit(78)


if __name__ == "__main__":
    main()
