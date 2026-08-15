#!/usr/bin/env python3
"""Create an ephemeral signed Playwright release registry for CI acceptance only."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.security_tools.opensandbox_supply_chain import (
    load_verified_worker_release_registry,
)

_BASE_IMAGE = re.compile(
    r"^ARG PYTHON_BASE_IMAGE=(?P<image>[^\s]+@sha256:[0-9a-f]{64})$",
    re.MULTILINE,
)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_release_cli(*arguments: str) -> None:
    subprocess.run(
        [sys.executable, "scripts/opensandbox_worker_release.py", *arguments],
        check=True,
        timeout=30,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()

    output = arguments.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    containerfile = Path("deploy/opensandbox-workers/playwright/Containerfile")
    match = _BASE_IMAGE.search(containerfile.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit("Playwright worker base image is not pinned by OCI SHA-256")

    version = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python3",
            arguments.image,
            "-c",
            "import importlib.metadata; print(importlib.metadata.version('playwright'))",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if version != "1.62.0":
        raise SystemExit(f"unexpected Playwright worker version: {version}")

    sbom_path = output / "sbom.spdx.json"
    provenance_path = output / "provenance.json"
    record_path = output / "record.json"
    registry_path = output / "registry.json"
    signature_path = output / "registry.sig.json"
    private_key = output / "private.pem"
    public_key = output / "public.pem"

    _write_json(
        sbom_path,
        {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "vulnhunter-opensandbox-playwright",
            "documentNamespace": "urn:vulnhunter:opensandbox:playwright:"
            + arguments.image.rsplit(":", 1)[-1],
            "creationInfo": {
                "created": datetime.now(UTC)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "creators": ["Tool: VulnHunter Playwright acceptance"],
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Playwright",
                    "name": "playwright",
                    "versionInfo": version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                }
            ],
        },
    )
    _write_json(
        provenance_path,
        {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {
                    "name": arguments.image.split("@", 1)[0],
                    "digest": {"sha256": arguments.image.rsplit(":", 1)[-1]},
                }
            ],
            "predicate": {
                "buildDefinition": {
                    "buildType": "vulnhunter:opensandbox:playwright:v1",
                    "externalParameters": {"source_commit": arguments.source_commit},
                    "resolvedDependencies": [
                        {
                            "uri": "oci://" + match.group("image").split("@", 1)[0],
                            "digest": {"sha256": match.group("image").rsplit(":", 1)[-1]},
                        }
                    ],
                }
            },
        },
    )
    _write_json(
        record_path,
        {
            "worker_id": "playwright",
            "release_id": "playwright-ci-" + arguments.source_commit[:12],
            "image": arguments.image,
            "sbom_sha256": _sha256(sbom_path),
            "provenance_sha256": _sha256(provenance_path),
            "source_commit": arguments.source_commit,
            "status": "approved",
            "rollback_of": None,
            "github_provenance_attestation_sha256": None,
            "github_sbom_attestation_sha256": None,
            "github_attestation_signer": None,
        },
    )

    _run_release_cli(
        "keygen",
        "--private-key",
        str(private_key),
        "--public-key",
        str(public_key),
    )
    _run_release_cli("registry", "--record", str(record_path), "--output", str(registry_path))
    _run_release_cli(
        "sign",
        "--registry",
        str(registry_path),
        "--private-key",
        str(private_key),
        "--public-key",
        str(public_key),
        "--signature",
        str(signature_path),
    )

    registry = load_verified_worker_release_registry(
        registry_path,
        signature_path,
        public_key,
    )
    release = registry.approved_release("playwright", arguments.image)
    private_key.unlink(missing_ok=True)

    verification = {
        "status": "accepted",
        "worker_id": release.worker_id,
        "release_id": release.release_id,
        "image": release.image,
        "sbom_sha256": release.sbom_sha256,
        "provenance_sha256": release.provenance_sha256,
        "registry_sha256": registry.registry_sha256,
        "key_id": registry.key_id,
    }
    _write_json(output / "verification.json", verification)
    print(json.dumps(verification, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
