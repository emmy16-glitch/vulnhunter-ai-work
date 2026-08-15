"""Signed release verification for approved OpenSandbox scanner workers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_IMAGE_DIGEST = re.compile(r"^.+@sha256:([0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_GITHUB_WORKFLOW_SIGNER = re.compile(
    r"^github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/"
    r"[A-Za-z0-9_.-]+\.ya?ml$"
)
_MAX_REGISTRY_BYTES = 1_000_000
_MAX_SIGNATURE_BYTES = 16_384
_MAX_PUBLIC_KEY_BYTES = 65_536

_RELEASE_V1_FIELDS = {
    "worker_id",
    "release_id",
    "image",
    "sbom_sha256",
    "provenance_sha256",
    "source_commit",
    "status",
    "rollback_of",
}
_RELEASE_V2_FIELDS = _RELEASE_V1_FIELDS | {
    "github_provenance_attestation_sha256",
    "github_sbom_attestation_sha256",
    "github_attestation_signer",
}


class WorkerReleaseVerificationError(ValueError):
    """Raised when a worker release registry cannot be trusted."""


@dataclass(frozen=True)
class ApprovedWorkerRelease:
    """One signed worker release identity and its supply-chain evidence digests."""

    worker_id: str
    release_id: str
    image: str
    sbom_sha256: str
    provenance_sha256: str
    source_commit: str
    status: Literal["candidate", "approved", "revoked"]
    rollback_of: str | None = None
    github_provenance_attestation_sha256: str | None = None
    github_sbom_attestation_sha256: str | None = None
    github_attestation_signer: str | None = None

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.worker_id) is None:
            raise WorkerReleaseVerificationError("worker release worker_id is invalid")
        if _IDENTIFIER.fullmatch(self.release_id) is None:
            raise WorkerReleaseVerificationError("worker release release_id is invalid")
        if _IMAGE_DIGEST.fullmatch(self.image) is None:
            raise WorkerReleaseVerificationError(
                "worker release image must be pinned by sha256 digest"
            )
        if _SHA256.fullmatch(self.sbom_sha256) is None:
            raise WorkerReleaseVerificationError("worker release SBOM digest is invalid")
        if _SHA256.fullmatch(self.provenance_sha256) is None:
            raise WorkerReleaseVerificationError("worker release provenance digest is invalid")
        if _SOURCE_COMMIT.fullmatch(self.source_commit) is None:
            raise WorkerReleaseVerificationError("worker release source commit is invalid")
        if self.status not in {"candidate", "approved", "revoked"}:
            raise WorkerReleaseVerificationError(
                "worker release status must be candidate, approved, or revoked"
            )
        if self.rollback_of is not None and _IDENTIFIER.fullmatch(self.rollback_of) is None:
            raise WorkerReleaseVerificationError("worker release rollback_of is invalid")

        attestation_values = (
            self.github_provenance_attestation_sha256,
            self.github_sbom_attestation_sha256,
            self.github_attestation_signer,
        )
        if any(value is not None for value in attestation_values):
            if any(value is None for value in attestation_values):
                raise WorkerReleaseVerificationError(
                    "worker GitHub attestation identity must be complete"
                )
            if _SHA256.fullmatch(self.github_provenance_attestation_sha256 or "") is None:
                raise WorkerReleaseVerificationError(
                    "worker GitHub provenance attestation digest is invalid"
                )
            if _SHA256.fullmatch(self.github_sbom_attestation_sha256 or "") is None:
                raise WorkerReleaseVerificationError(
                    "worker GitHub SBOM attestation digest is invalid"
                )
            if _GITHUB_WORKFLOW_SIGNER.fullmatch(self.github_attestation_signer or "") is None:
                raise WorkerReleaseVerificationError(
                    "worker GitHub attestation signer workflow is invalid"
                )

    @property
    def image_sha256(self) -> str:
        match = _IMAGE_DIGEST.fullmatch(self.image)
        if match is None:  # guarded by __post_init__
            raise WorkerReleaseVerificationError("worker release image digest disappeared")
        return match.group(1)

    @property
    def has_github_attestations(self) -> bool:
        return all(
            value is not None
            for value in (
                self.github_provenance_attestation_sha256,
                self.github_sbom_attestation_sha256,
                self.github_attestation_signer,
            )
        )


@dataclass(frozen=True)
class VerifiedWorkerReleaseRegistry:
    """A registry whose Ed25519 signature and schema have been verified."""

    releases: tuple[ApprovedWorkerRelease, ...]
    registry_sha256: str
    key_id: str

    def approved_release(self, worker_id: str, image: str) -> ApprovedWorkerRelease:
        matches = [
            release
            for release in self.releases
            if release.worker_id == worker_id and release.image == image
        ]
        if not matches:
            raise WorkerReleaseVerificationError(
                f"OpenSandbox {worker_id} image is absent from the signed release registry"
            )
        approved = [release for release in matches if release.status == "approved"]
        if not approved:
            raise WorkerReleaseVerificationError(
                f"OpenSandbox {worker_id} image has no approved signed release"
            )
        if len(approved) != 1:
            raise WorkerReleaseVerificationError(
                f"OpenSandbox {worker_id} image has multiple approved signed releases"
            )
        return approved[0]


def load_verified_worker_release_registry(
    registry_file: Path,
    signature_file: Path,
    public_key_file: Path,
) -> VerifiedWorkerReleaseRegistry:
    """Load and verify one canonical JSON registry plus detached Ed25519 signature."""

    registry_payload = _load_json_object(
        _read_regular_file(registry_file, maximum_bytes=_MAX_REGISTRY_BYTES),
        label="worker release registry",
    )
    if set(registry_payload) != {"schema_version", "releases"}:
        raise WorkerReleaseVerificationError("worker release registry has unexpected fields")
    schema_version = registry_payload.get("schema_version")
    if schema_version not in {1, 2}:
        raise WorkerReleaseVerificationError(
            "worker release registry schema version is unsupported"
        )
    raw_releases = registry_payload.get("releases")
    if not isinstance(raw_releases, list) or not raw_releases:
        raise WorkerReleaseVerificationError("worker release registry must contain releases")

    releases = tuple(
        _parse_release(value, schema_version=schema_version) for value in raw_releases
    )
    _validate_release_history(releases)
    canonical_registry = canonical_json_bytes(registry_payload)

    signature_payload = _load_json_object(
        _read_regular_file(signature_file, maximum_bytes=_MAX_SIGNATURE_BYTES),
        label="worker release signature",
    )
    if set(signature_payload) != {"schema_version", "algorithm", "key_id", "signature"}:
        raise WorkerReleaseVerificationError("worker release signature has unexpected fields")
    if signature_payload.get("schema_version") != 1:
        raise WorkerReleaseVerificationError(
            "worker release signature schema version is unsupported"
        )
    if signature_payload.get("algorithm") != "ed25519":
        raise WorkerReleaseVerificationError("worker release signature algorithm must be ed25519")

    public_key_bytes = _read_regular_file(
        public_key_file,
        maximum_bytes=_MAX_PUBLIC_KEY_BYTES,
    )
    public_key, key_id = _load_ed25519_public_key(public_key_bytes)
    if signature_payload.get("key_id") != key_id:
        raise WorkerReleaseVerificationError("worker release signature key_id does not match key")
    signature = _decode_signature(signature_payload.get("signature"))
    try:
        from cryptography.exceptions import InvalidSignature

        public_key.verify(signature, canonical_registry)
    except InvalidSignature as exc:
        raise WorkerReleaseVerificationError(
            "worker release registry signature verification failed"
        ) from exc

    return VerifiedWorkerReleaseRegistry(
        releases=releases,
        registry_sha256=hashlib.sha256(canonical_registry).hexdigest(),
        key_id=key_id,
    )


def canonical_json_bytes(payload: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes used for signing and hashing."""

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_file(path: Path, *, maximum_bytes: int = 50_000_000) -> str:
    """Hash a bounded regular non-symlink file."""

    return hashlib.sha256(_read_regular_file(path, maximum_bytes=maximum_bytes)).hexdigest()


def public_key_id(public_key_bytes: bytes) -> str:
    """Return the stable SHA-256 key identifier for an Ed25519 PEM public key."""

    _, key_id = _load_ed25519_public_key(public_key_bytes)
    return key_id


def _parse_release(value: object, *, schema_version: int) -> ApprovedWorkerRelease:
    if not isinstance(value, dict):
        raise WorkerReleaseVerificationError("worker release entry must be a JSON object")
    expected = _RELEASE_V1_FIELDS if schema_version == 1 else _RELEASE_V2_FIELDS
    if set(value) != expected:
        raise WorkerReleaseVerificationError("worker release entry has unexpected fields")
    if not all(
        isinstance(value.get(field), str)
        for field in (
            "worker_id",
            "release_id",
            "image",
            "sbom_sha256",
            "provenance_sha256",
            "source_commit",
            "status",
        )
    ):
        raise WorkerReleaseVerificationError("worker release entry contains invalid field types")
    rollback_of = value.get("rollback_of")
    if rollback_of is not None and not isinstance(rollback_of, str):
        raise WorkerReleaseVerificationError("worker release rollback_of must be text or null")
    status = value["status"]
    allowed_statuses = {"approved", "revoked"} if schema_version == 1 else {
        "candidate",
        "approved",
        "revoked",
    }
    if status not in allowed_statuses:
        raise WorkerReleaseVerificationError("worker release status is unsupported")

    github_provenance = None
    github_sbom = None
    github_signer = None
    if schema_version == 2:
        for field in (
            "github_provenance_attestation_sha256",
            "github_sbom_attestation_sha256",
            "github_attestation_signer",
        ):
            if value.get(field) is not None and not isinstance(value.get(field), str):
                raise WorkerReleaseVerificationError(
                    "worker GitHub attestation fields must be text or null"
                )
        github_provenance = value.get("github_provenance_attestation_sha256")
        github_sbom = value.get("github_sbom_attestation_sha256")
        github_signer = value.get("github_attestation_signer")

    return ApprovedWorkerRelease(
        worker_id=value["worker_id"],
        release_id=value["release_id"],
        image=value["image"],
        sbom_sha256=value["sbom_sha256"],
        provenance_sha256=value["provenance_sha256"],
        source_commit=value["source_commit"],
        status=status,
        rollback_of=rollback_of,
        github_provenance_attestation_sha256=github_provenance,
        github_sbom_attestation_sha256=github_sbom,
        github_attestation_signer=github_signer,
    )


def _validate_release_history(releases: tuple[ApprovedWorkerRelease, ...]) -> None:
    release_by_id: dict[str, ApprovedWorkerRelease] = {}
    approved_by_image: set[tuple[str, str]] = set()
    for release in releases:
        if release.release_id in release_by_id:
            raise WorkerReleaseVerificationError("worker release IDs must be unique")
        release_by_id[release.release_id] = release
        identity = (release.worker_id, release.image)
        if release.status == "approved" and identity in approved_by_image:
            raise WorkerReleaseVerificationError(
                "worker image must not have multiple approved release records"
            )
        if release.status == "approved":
            approved_by_image.add(identity)

    for release in releases:
        if release.rollback_of is None:
            continue
        predecessor = release_by_id.get(release.rollback_of)
        if predecessor is None:
            raise WorkerReleaseVerificationError(
                "worker release rollback_of must reference an existing release"
            )
        if predecessor.release_id == release.release_id:
            raise WorkerReleaseVerificationError("worker release cannot roll back itself")
        if predecessor.worker_id != release.worker_id:
            raise WorkerReleaseVerificationError(
                "worker release rollback_of must reference the same worker"
            )


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise WorkerReleaseVerificationError("worker release signature must be base64 text")
    try:
        signature = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise WorkerReleaseVerificationError(
            "worker release signature is not valid base64"
        ) from exc
    if len(signature) != 64:
        raise WorkerReleaseVerificationError("worker release Ed25519 signature must be 64 bytes")
    return signature


def _load_ed25519_public_key(public_key_bytes: bytes):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise WorkerReleaseVerificationError(
            "worker release verification requires the OpenSandbox cryptography dependency"
        ) from exc
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except (TypeError, ValueError) as exc:
        raise WorkerReleaseVerificationError("worker release public key is invalid PEM") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise WorkerReleaseVerificationError("worker release public key must be Ed25519")
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key, "sha256:" + hashlib.sha256(der).hexdigest()


def _load_json_object(data: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise WorkerReleaseVerificationError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerReleaseVerificationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise WorkerReleaseVerificationError(f"{label} must be a JSON object")
    return payload


def _read_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WorkerReleaseVerificationError(f"worker release file is unavailable: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise WorkerReleaseVerificationError(
                "worker release inputs must be regular non-symlink files"
            )
        if metadata.st_size > maximum_bytes:
            raise WorkerReleaseVerificationError("worker release input exceeds its maximum size")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum_bytes:
            raise WorkerReleaseVerificationError("worker release input exceeds its maximum size")
        if len(data) != metadata.st_size:
            raise WorkerReleaseVerificationError("worker release input changed while being read")
        return data
    finally:
        os.close(descriptor)
