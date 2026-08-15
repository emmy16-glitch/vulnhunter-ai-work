from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "opensandbox_worker_release.py"
_SIGNER = (
    "github.com/emmy16-glitch/vulnhunter-ai-work/.github/workflows/opensandbox-worker-release.yml"
)
_IMAGE = "ghcr.io/emmy16-glitch/vulnhunter-opensandbox-bandit@sha256:" + "a" * 64


def _run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *arguments],
        cwd=_REPO_ROOT,
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_candidate_can_only_become_runtime_selectable_after_offline_promotion_and_signing(
    tmp_path: pathlib.Path,
) -> None:
    sbom = tmp_path / "sbom.spdx.json"
    provenance = tmp_path / "provenance.json"
    github_provenance = tmp_path / "github-provenance.attestation.jsonl"
    github_sbom = tmp_path / "github-sbom.attestation.jsonl"
    candidate = tmp_path / "candidate.json"
    approved = tmp_path / "approved.json"
    registry = tmp_path / "registry.json"
    signature = tmp_path / "registry.sig.json"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
    provenance.write_text('{"predicateType":"https://slsa.dev/provenance/v1"}\n', encoding="utf-8")
    github_provenance.write_text('{"verificationMaterial":"provenance"}\n', encoding="utf-8")
    github_sbom.write_text('{"verificationMaterial":"sbom"}\n', encoding="utf-8")

    _run(
        "record",
        "--worker-id",
        "bandit",
        "--release-id",
        "bandit-prod-20260815",
        "--image",
        _IMAGE,
        "--sbom",
        str(sbom),
        "--provenance",
        str(provenance),
        "--source-commit",
        "1" * 40,
        "--status",
        "candidate",
        "--github-provenance-attestation",
        str(github_provenance),
        "--github-sbom-attestation",
        str(github_sbom),
        "--github-attestation-signer",
        _SIGNER,
        "--output",
        str(candidate),
    )
    candidate_payload = json.loads(candidate.read_text(encoding="utf-8"))
    assert candidate_payload["status"] == "candidate"
    assert candidate_payload["github_provenance_attestation_sha256"] == _sha256(
        github_provenance
    )
    assert candidate_payload["github_sbom_attestation_sha256"] == _sha256(github_sbom)
    assert candidate_payload["github_attestation_signer"] == _SIGNER

    _run(
        "promote",
        "--candidate",
        str(candidate),
        "--status",
        "approved",
        "--output",
        str(approved),
    )
    approved_payload = json.loads(approved.read_text(encoding="utf-8"))
    assert approved_payload["status"] == "approved"
    assert approved_payload["image"] == candidate_payload["image"]
    assert approved_payload["github_provenance_attestation_sha256"] == candidate_payload[
        "github_provenance_attestation_sha256"
    ]

    _run("registry", "--record", str(approved), "--output", str(registry))
    assert json.loads(registry.read_text(encoding="utf-8"))["schema_version"] == 2

    _run("keygen", "--private-key", str(private_key), "--public-key", str(public_key))
    _run(
        "sign",
        "--registry",
        str(registry),
        "--private-key",
        str(private_key),
        "--public-key",
        str(public_key),
        "--signature",
        str(signature),
    )
    verified = _run(
        "verify",
        "--registry",
        str(registry),
        "--signature",
        str(signature),
        "--public-key",
        str(public_key),
        "--worker-id",
        "bandit",
        "--image",
        _IMAGE,
    )
    receipt = json.loads(verified.stdout)
    assert receipt["status"] == "accepted"
    assert receipt["release_id"] == "bandit-prod-20260815"
    assert receipt["github_attestation_signer"] == _SIGNER
    assert receipt["github_provenance_attestation_sha256"] == _sha256(github_provenance)
    assert receipt["github_sbom_attestation_sha256"] == _sha256(github_sbom)


def test_promote_refuses_non_candidate_record(tmp_path: pathlib.Path) -> None:
    record = tmp_path / "approved.json"
    record.write_text(
        json.dumps(
            {
                "worker_id": "bandit",
                "release_id": "bandit-release-1",
                "image": _IMAGE,
                "sbom_sha256": "b" * 64,
                "provenance_sha256": "c" * 64,
                "source_commit": "d" * 40,
                "status": "approved",
                "rollback_of": None,
                "github_provenance_attestation_sha256": "e" * 64,
                "github_sbom_attestation_sha256": "f" * 64,
                "github_attestation_signer": _SIGNER,
            }
        ),
        encoding="utf-8",
    )

    result = _run(
        "promote",
        "--candidate",
        str(record),
        "--status",
        "approved",
        "--output",
        str(tmp_path / "out.json"),
        check=False,
    )

    assert result.returncode != 0
    assert "only a candidate" in result.stderr


def test_provenance_binds_immutable_base_image(tmp_path: pathlib.Path) -> None:
    containerfile = tmp_path / "Containerfile"
    output = tmp_path / "provenance.json"
    base_digest = "b" * 64
    containerfile.write_text(
        f"ARG PYTHON_BASE_IMAGE=python:3.12-slim-bookworm@sha256:{base_digest}\n"
        "FROM ${PYTHON_BASE_IMAGE}\n",
        encoding="utf-8",
    )

    _run(
        "provenance",
        "--worker-id",
        "bandit",
        "--image",
        _IMAGE,
        "--containerfile",
        str(containerfile),
        "--source-commit",
        "1" * 40,
        "--builder-id",
        "https://github.com/emmy16-glitch/vulnhunter-ai-work/.github/workflows/"
        "opensandbox-worker-release.yml",
        "--output",
        str(output),
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    dependencies = payload["predicate"]["buildDefinition"]["resolvedDependencies"]

    assert any(
        item.get("uri") == "oci://python:3.12-slim-bookworm"
        and item.get("digest", {}).get("sha256") == base_digest
        for item in dependencies
    )


def test_provenance_refuses_mutable_base_image(tmp_path: pathlib.Path) -> None:
    containerfile = tmp_path / "Containerfile"
    containerfile.write_text(
        "ARG PYTHON_BASE_IMAGE=python:3.12-slim-bookworm\nFROM ${PYTHON_BASE_IMAGE}\n",
        encoding="utf-8",
    )

    result = _run(
        "provenance",
        "--worker-id",
        "bandit",
        "--image",
        _IMAGE,
        "--containerfile",
        str(containerfile),
        "--source-commit",
        "1" * 40,
        "--output",
        str(tmp_path / "provenance.json"),
        check=False,
    )

    assert result.returncode != 0
    assert "immutable sha256 digest" in result.stderr
