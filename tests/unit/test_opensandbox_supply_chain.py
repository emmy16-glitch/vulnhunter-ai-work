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
) -> dict[str, object]:
    return {
        "worker_id": worker_id,
        "release_id": release_id,
        "image": f"registry.example/vulnhunter/{worker_id}@sha256:{image_character * 64}",
        "sbom_sha256": "b" * 64,
        "provenance_sha256": "c" * 64,
        "source_commit": "d" * 40,
        "status": status,
        "rollback_of": None,
    }


def _write_signed_bundle(
    tmp_path: Path,
    releases: list[dict[str, object]],
) -> tuple[Path, Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    registry_payload = {"schema_version": 1, "releases": releases}
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
    assert registry.registry_sha256
    assert registry.key_id.startswith("sha256:")


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

    with pytest.raises(WorkerReleaseVerificationError, match="is revoked"):
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


def test_duplicate_release_identity_is_rejected_even_when_signed(tmp_path: Path) -> None:
    release = _release()
    duplicate = dict(release)
    duplicate["release_id"] = "bandit-release-2"
    registry_file, signature_file, public_key_file = _write_signed_bundle(
        tmp_path,
        [release, duplicate],
    )

    with pytest.raises(WorkerReleaseVerificationError, match="image identities must be unique"):
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

    with pytest.raises(WorkerReleaseVerificationError, match="regular non-symlink"):
        load_verified_worker_release_registry(
            symlink,
            signature_file,
            public_key_file,
        )
