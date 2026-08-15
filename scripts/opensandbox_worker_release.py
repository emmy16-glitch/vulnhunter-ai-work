"""Build, attest, promote, sign, and verify OpenSandbox worker release evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.security_tools.opensandbox_supply_chain import (
    canonical_json_bytes,
    load_verified_worker_release_registry,
    public_key_id,
    sha256_file,
)

_IMAGE = re.compile(r"^(?P<name>.+)@sha256:(?P<digest>[0-9a-f]{64})$")
_PINNED_BASE = re.compile(
    r"^ARG PYTHON_BASE_IMAGE=(?P<image>[^\s]+@sha256:[0-9a-f]{64})$",
    re.MULTILINE,
)
_RECORD_V2_FIELDS = {
    "worker_id",
    "release_id",
    "image",
    "sbom_sha256",
    "provenance_sha256",
    "source_commit",
    "status",
    "rollback_of",
    "github_provenance_attestation_sha256",
    "github_sbom_attestation_sha256",
    "github_attestation_signer",
}
_DEFAULT_BUILDER_ID = (
    "https://github.com/emmy16-glitch/vulnhunter-ai-work/"
    ".github/workflows/opensandbox-worker.yml"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)

    sbom = subparsers.add_parser("sbom")
    sbom.add_argument("--worker-id", choices=("bandit", "nuclei"), required=True)
    sbom.add_argument("--image", required=True)
    sbom.add_argument("--output", type=Path, required=True)

    provenance = subparsers.add_parser("provenance")
    provenance.add_argument("--worker-id", choices=("bandit", "nuclei"), required=True)
    provenance.add_argument("--image", required=True)
    provenance.add_argument("--containerfile", type=Path, required=True)
    provenance.add_argument("--source-commit", required=True)
    provenance.add_argument("--builder-id", default=_DEFAULT_BUILDER_ID)
    provenance.add_argument("--output", type=Path, required=True)

    record = subparsers.add_parser("record")
    record.add_argument("--worker-id", choices=("bandit", "nuclei"), required=True)
    record.add_argument("--release-id", required=True)
    record.add_argument("--image", required=True)
    record.add_argument("--sbom", type=Path, required=True)
    record.add_argument("--provenance", type=Path, required=True)
    record.add_argument("--source-commit", required=True)
    record.add_argument(
        "--status",
        choices=("candidate", "approved", "revoked"),
        default="approved",
    )
    record.add_argument("--rollback-of")
    record.add_argument("--github-provenance-attestation", type=Path)
    record.add_argument("--github-sbom-attestation", type=Path)
    record.add_argument("--github-attestation-signer")
    record.add_argument("--output", type=Path, required=True)

    promote = subparsers.add_parser("promote")
    promote.add_argument("--candidate", type=Path, required=True)
    promote.add_argument("--status", choices=("approved", "revoked"), required=True)
    promote.add_argument("--rollback-of")
    promote.add_argument("--output", type=Path, required=True)

    registry = subparsers.add_parser("registry")
    registry.add_argument("--record", type=Path, action="append", required=True)
    registry.add_argument("--output", type=Path, required=True)

    sign = subparsers.add_parser("sign")
    sign.add_argument("--registry", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True)
    sign.add_argument("--signature", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--signature", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--worker-id", choices=("bandit", "nuclei"), required=True)
    verify.add_argument("--image", required=True)

    return parser


def _image_parts(image: str) -> tuple[str, str]:
    match = _IMAGE.fullmatch(image)
    if match is None:
        raise SystemExit("worker image must be an immutable repository @sha256 digest")
    return match.group("name"), match.group("digest")


def _write_json(path: Path, payload: object, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(data)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _keygen(private_key_path: Path, public_key_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_secret(private_key_path, private_bytes)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_bytes(public_bytes)
    public_key_path.chmod(0o644)


def _docker_output(arguments: list[str]) -> str:
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout.strip() or result.stderr.strip()


def _sbom(worker_id: str, image: str, output: Path) -> None:
    image_name, image_digest = _image_parts(image)
    package_output = _docker_output(
        [
            "--entrypoint",
            "dpkg-query",
            image,
            "-W",
            "-f=${Package}\\t${Version}\\n",
        ]
    )
    scanner_command = (
        ["--entrypoint", "/usr/local/bin/bandit", image, "--version"]
        if worker_id == "bandit"
        else ["--entrypoint", "/usr/local/bin/nuclei", image, "-version"]
    )
    scanner_version = _docker_output(scanner_command).splitlines()[0][:500]
    packages = []
    for index, line in enumerate(sorted(package_output.splitlines()), start=1):
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{index}",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
    payload = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"vulnhunter-opensandbox-{worker_id}",
        "documentNamespace": f"urn:vulnhunter:opensandbox:{worker_id}:{image_digest}",
        "creationInfo": {
            "created": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: VulnHunter OpenSandbox worker release generator"],
        },
        "documentDescribes": ["SPDXRef-WorkerImage"],
        "packages": [
            {
                "SPDXID": "SPDXRef-WorkerImage",
                "name": image_name,
                "versionInfo": image_digest,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:oci/{worker_id}@{image_digest}",
                    }
                ],
                "comment": scanner_version,
            },
            *packages,
        ],
    }
    _write_json(output, payload)


def _pinned_base_image(containerfile: Path) -> str:
    text = containerfile.read_text(encoding="utf-8")
    match = _PINNED_BASE.search(text)
    if match is None:
        raise SystemExit(
            "worker Containerfile must declare PYTHON_BASE_IMAGE with an immutable sha256 digest"
        )
    image = match.group("image")
    _image_parts(image)
    return image


def _provenance(
    worker_id: str,
    image: str,
    containerfile: Path,
    source_commit: str,
    builder_id: str,
    output: Path,
) -> None:
    image_name, image_digest = _image_parts(image)
    base_image = _pinned_base_image(containerfile)
    base_name, base_digest = _image_parts(base_image)
    containerfile_digest = sha256_file(containerfile, maximum_bytes=1_000_000)
    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": image_name, "digest": {"sha256": image_digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://vulnhunter.local/build-types/opensandbox-worker/v2",
                "externalParameters": {
                    "worker_id": worker_id,
                    "containerfile": str(containerfile),
                    "base_image": base_image,
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/emmy16-glitch/vulnhunter-ai-work",
                        "digest": {"gitCommit": source_commit},
                    },
                    {
                        "uri": f"file:{containerfile}",
                        "digest": {"sha256": containerfile_digest},
                    },
                    {
                        "uri": f"oci://{base_name}",
                        "digest": {"sha256": base_digest},
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": source_commit},
            },
        },
    }
    _write_json(output, payload)


def _record(args: argparse.Namespace) -> None:
    _image_parts(args.image)
    attestation_values = (
        args.github_provenance_attestation,
        args.github_sbom_attestation,
        args.github_attestation_signer,
    )
    if any(value is not None for value in attestation_values) and any(
        value is None for value in attestation_values
    ):
        raise SystemExit("GitHub provenance, SBOM, and signer evidence must be provided together")
    payload = {
        "worker_id": args.worker_id,
        "release_id": args.release_id,
        "image": args.image,
        "sbom_sha256": sha256_file(args.sbom),
        "provenance_sha256": sha256_file(args.provenance),
        "source_commit": args.source_commit,
        "status": args.status,
        "rollback_of": args.rollback_of,
        "github_provenance_attestation_sha256": (
            sha256_file(args.github_provenance_attestation)
            if args.github_provenance_attestation is not None
            else None
        ),
        "github_sbom_attestation_sha256": (
            sha256_file(args.github_sbom_attestation)
            if args.github_sbom_attestation is not None
            else None
        ),
        "github_attestation_signer": args.github_attestation_signer,
    }
    _write_json(args.output, payload)


def _load_record(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != _RECORD_V2_FIELDS:
        raise SystemExit(f"release record is not schema-v2: {path}")
    return payload


def _promote(candidate: Path, status: str, rollback_of: str | None, output: Path) -> None:
    payload = _load_record(candidate)
    if payload.get("status") != "candidate":
        raise SystemExit("only a candidate worker release record may be promoted")
    promoted = dict(payload)
    promoted["status"] = status
    promoted["rollback_of"] = rollback_of
    _write_json(output, promoted)


def _registry(records: list[Path], output: Path) -> None:
    releases = [_load_record(path) for path in records]
    _write_json(output, {"schema_version": 2, "releases": releases})


def _sign(registry: Path, private_key_path: Path, public_key_path: Path, signature: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    payload = json.loads(registry.read_text(encoding="utf-8"))
    canonical = canonical_json_bytes(payload)
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SystemExit("worker release private key must be Ed25519")
    public_bytes = public_key_path.read_bytes()
    expected_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    loaded_public = serialization.load_pem_public_key(public_bytes)
    loaded_der = loaded_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if loaded_der != expected_public:
        raise SystemExit("worker release private/public key pair does not match")
    signed = private_key.sign(canonical)

    import base64

    _write_json(
        signature,
        {
            "schema_version": 1,
            "algorithm": "ed25519",
            "key_id": public_key_id(public_bytes),
            "signature": base64.b64encode(signed).decode("ascii"),
        },
    )


def _verify(args: argparse.Namespace) -> None:
    registry = load_verified_worker_release_registry(
        args.registry,
        args.signature,
        args.public_key,
    )
    release = registry.approved_release(args.worker_id, args.image)
    print(
        json.dumps(
            {
                "status": "accepted",
                "worker_id": release.worker_id,
                "release_id": release.release_id,
                "image": release.image,
                "sbom_sha256": release.sbom_sha256,
                "provenance_sha256": release.provenance_sha256,
                "source_commit": release.source_commit,
                "github_provenance_attestation_sha256": (
                    release.github_provenance_attestation_sha256
                ),
                "github_sbom_attestation_sha256": release.github_sbom_attestation_sha256,
                "github_attestation_signer": release.github_attestation_signer,
                "registry_sha256": registry.registry_sha256,
                "key_id": registry.key_id,
            },
            sort_keys=True,
        )
    )


def main() -> None:
    args = _parser().parse_args()
    if args.command == "keygen":
        _keygen(args.private_key, args.public_key)
    elif args.command == "sbom":
        _sbom(args.worker_id, args.image, args.output)
    elif args.command == "provenance":
        _provenance(
            args.worker_id,
            args.image,
            args.containerfile,
            args.source_commit,
            args.builder_id,
            args.output,
        )
    elif args.command == "record":
        _record(args)
    elif args.command == "promote":
        _promote(args.candidate, args.status, args.rollback_of, args.output)
    elif args.command == "registry":
        _registry(args.record, args.output)
    elif args.command == "sign":
        _sign(args.registry, args.private_key, args.public_key, args.signature)
    elif args.command == "verify":
        _verify(args)
    else:  # pragma: no cover
        raise SystemExit(f"unsupported command: {args.command}")


if __name__ == "__main__":
    main()
