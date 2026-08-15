from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnhunter.security_tools.opensandbox_supply_chain import (
    WorkerReleaseVerificationError,
    canonical_json_bytes,
    load_verified_worker_release_registry,
    public_key_id,
)


def _release(
    *,
    worker_id: str = "bandit",
    image_character: str = "a",
    release_id: str = "bandit-release-1",
    status: str = "approved",
    rollback_of: str | None = None,
) -> dict[str, object]:
    return {
        "worker_id": worker_id,
        "release_id": release_id,
        "image": f"registry.example/vulnhunter/{worker_id}@sha256:{image_character * 64}",
        "sbom_sha256": "b" * 64,
        "provenance_sha256": "c" * 64,
        "source_commit": "d" * 40,
        "status": status,
        "rollback_of": rollback_of,
    }


def _release_v2(
    *,
    worker_id: str = "bandit",
    image_character: str = "a",
    release_id: str = "bandit-release-1",
    status: str = "approved",
    rollback_of: str | None = None,
    with_attestations: bool = True,
) -> dict[str, object]:
    payload = _release(
        worker_id=worker_id,
        image_character=image_character,
        release_id=release_id,
        status=status,
        rollback_of=rollback_of,
    )
    payload.update(
        {
            "github_provenance_attestation_sha256": "e" * 64 if with_attestations else None,
            "github_sbom_attestation_sha256": "f" * 64 if with_attestations else None,
            "github_attestation_signer": (
                "github.com/emmy16-glitch/vulnhunter-ai-work/.github/workflows/"
                "opensandbox-worker-release.yml"
                if with_attestations
                else None
            ),
        }
    )
    return payload


def _write_signed_bundle(
    tmp_path: Path,
    releases: list[dict[str, object]],
    *,
    schema_version: int = 1,
) -> tuple[Path, Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    registry_payload = {"schema_version": schema_version, "releases": releases}
    signature = private_key.sign(canonical_json_bytes(registry_payload))

    registry = tmp_path / "releases.json"
    signature_file = tmp_path / "releases.sig.json"
    public_key_file = tmp_path / "releases.pub.pem"
    registry.write_text(json.dumps(registry_payload, indent=2), encoding="utf-8")
    signature_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "algorithm": "ed25519",
                "key_id": public_key_id(public_bytes),
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )
    public_key_file.write_bytes(public_bytes)
    return registry, signature_file, public_key_file


def test_verified_registry_returns_exact_approved_release(tmp_path: Path) -> None:
    release = _release()
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
    )

    registry = load_verified_worker_release_registry(
        registry_file,
        signature_file,
        public_key_file,
    )
    approved = registry.approved_release("bandit", str(release["image"]))

    assert approved.release_id == "bandit-release-1"
    assert approved.sbom_sha256 == "b" * 64
    assert approved.provenance_sha256 == "c" * 64
    assert approved.has_github_attestations is False
    assert registry.registry_sha256
    assert registry.key_id.startswith("sha256:")


def test_v2_registry_binds_github_attestation_identity(tmp_path: Path) -> None:
    release = _release_v2()
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
        schema_version=2,
    )

    registry = load_verified_worker_release_registry(
        registry_file,
        signature_file,
        public_key_file,
    )
    approved = registry.approved_release("bandit", str(release["image"]))

    assert approved.github_provenance_attestation_sha256 == "e" * 64
    assert approved.github_sbom_attestation_sha256 == "f" * 64
    assert approved.github_attestation_signer == (
        "github.com/emmy16-glitch/vulnhunter-ai-work/.github/workflows/"
        "opensandbox-worker-release.yml"
    )
    assert approved.has_github_attestations is True


def test_candidate_release_is_never_selectable(tmp_path: Path) -> None:
    release = _release_v2(status="candidate")
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
        schema_version=2,
    )
    registry = load_verified_worker_release_registry(
        registry_file,
        signature_file,
        public_key_file,
    )

    with pytest.raises(WorkerReleaseVerificationError, match="has no approved signed release"):
        registry.approved_release("bandit", str(release["image"]))


def test_partial_github_attestation_identity_is_rejected(tmp_path: Path) -> None:
    release = _release_v2()
    release["github_sbom_attestation_sha256"] = None
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
        schema_version=2,
    )

    with pytest.raises(
        WorkerReleaseVerificationError,
        match="attestation identity must be complete",
    ):
        load_verified_worker_release_registry(
            registry_file,
            signature_file,
            public_key_file,
        )


def test_invalid_github_attestation_signer_is_rejected(tmp_path: Path) -> None:
    release = _release_v2()
    release["github_attestation_signer"] = "https://example.invalid/release.yml"
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
        schema_version=2,
    )

    with pytest.raises(WorkerReleaseVerificationError, match="signer workflow is invalid"):
        load_verified_worker_release_registry(
            registry_file,
            signature_file,
            public_key_file,
        )


def test_registry_tampering_invalidates_signature(tmp_path: Path) -> None:
    release = _release()
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
    )
    payload = json.loads(registry_file.read_text(encoding="utf-8"))
    payload["releases"][0]["sbom_sha256"] = "e" * 64
    registry_file.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(WorkerReleaseVerificationError, match="signature verification failed"):
        load_verified_worker_release_registry(
            registry_file,
            signature_file,
            public_key_file,
        )


def test_revoked_release_is_never_selectable(tmp_path: Path) -> None:
    release = _release(status="revoked")
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
    )
    registry = load_verified_worker_release_registry(
        registry_file,
        signature_file,
        public_key_file,
    )

    with pytest.raises(WorkerReleaseVerificationError, match="has no approved signed release"):
        registry.approved_release("bandit", str(release["image"]))


def test_unlisted_digest_is_rejected(tmp_path: Path) -> None:
    release = _release()
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
    )
    registry = load_verified_worker_release_registry(
        registry_file,
        signature_file,
        public_key_file,
    )

    other_image = "registry.example/vulnhunter/bandit@sha256:" + "f" * 64
    with pytest.raises(WorkerReleaseVerificationError, match="absent from the signed"):
        registry.approved_release("bandit", other_image)


def test_multiple_approved_records_for_same_image_are_rejected(tmp_path: Path) -> None:
    release = _release()
    duplicate = dict(release)
    duplicate["release_id"] = "bandit-release-2"
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release, duplicate],
    )

    with pytest.raises(WorkerReleaseVerificationError, match="multiple approved release records"):
        load_verified_worker_release_registry(
            registry_file,
            signature_file,
            public_key_file,
        )


def test_rollback_can_reapprove_historical_image_after_revocation(tmp_path: Path) -> None:
    historical = _release(status="revoked")
    replacement = _release(
        image_character="e",
        release_id="bandit-release-2",
        status="revoked",
    )
    rollback = _release(
        release_id="bandit-release-3",
        status="approved",
        rollback_of="bandit-release-2",
    )
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [historical, replacement, rollback],
    )

    registry = load_verified_worker_release_registry(
        registry_file,
        signature_file,
        public_key_file,
    )
    approved = registry.approved_release("bandit", str(rollback["image"]))

    assert approved.release_id == "bandit-release-3"
    assert approved.rollback_of == "bandit-release-2"


def test_rollback_must_reference_existing_same_worker_release(tmp_path: Path) -> None:
    rollback = _release(
        release_id="bandit-release-2",
        rollback_of="missing-release",
    )
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [rollback],
    )
    with pytest.raises(WorkerReleaseVerificationError, match="reference an existing release"):
        load_verified_worker_release_registry(
            registry_file,
            signature_file,
            public_key_file,
        )

    nuclei = _release(
        worker_id="nuclei",
        image_character="f",
        release_id="nuclei-release-1",
        status="revoked",
    )
    cross_worker = _release(
        release_id="bandit-release-3",
        rollback_of="nuclei-release-1",
    )
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [nuclei, cross_worker],
    )
    with pytest.raises(WorkerReleaseVerificationError, match="same worker"):
        load_verified_worker_release_registry(
            registry_file,
            signature_file,
            public_key_file,
        )


def test_symlink_registry_is_rejected(tmp_path: Path) -> None:
    release = _release()
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release],
    )
    symlink = tmp_path / "releases-link.json"
    symlink.symlink_to(registry_file)

    with pytest.raises(WorkerReleaseVerificationError, match="regular non-symlink|unavailable"):
        load_verified_worker_release_registry(
            symlink,
            signature_file,
            public_key_file,
        )
