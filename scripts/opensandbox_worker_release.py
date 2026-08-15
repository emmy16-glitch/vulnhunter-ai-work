"""Build and verify signed supply-chain evidence for OpenSandbox worker releases."""

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
    provenance.add_argument("--output", type=Path, required=True)

    record = subparsers.add_parser("record")
    record.add_argument("--worker-id", choices=("bandit", "nuclei"), required=True)
    record.add_argument("--release-id", required=True)
    record.add_argument("--image", required=True)
    record.add_argument("--sbom", type=Path, required=True)
    record.add_argument("--provenance", type=Path, required=True)
    record.add_argument("--source-commit", required=True)
    record.add_argument("--status", choices=("approved", "revoked"), default="approved")
    record.add_argument("--rollback-of")
    record.add_argument("--output", type=Path, required=True)

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


def _provenance(
    worker_id: str,
    image: str,
    containerfile: Path,
    source_commit: str,
    output: Path,
) -> None:
    image_name, image_digest = _image_parts(image)
    containerfile_digest = sha256_file(containerfile, maximum_bytes=1_000_000)
    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": image_name, "digest": {"sha256": image_digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://vulnhunter.local/build-types/opensandbox-worker/v1",
                "externalParameters": {
                    "worker_id": worker_id,
                    "containerfile": str(containerfile),
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
                ],
            },
            "runDetails": {
                "builder": {
                    "id": (
                        "https://github.com/emmy16-glitch/vulnhunter-ai-work/"
                        ".github/workflows/opensandbox-worker.yml"
                    )
                },
                "metadata": {"invocationId": source_commit},
            },
        },
    }
    _write_json(output, payload)


def _record(args: argparse.Namespace) -> None:
    _image_parts(args.image)
    payload = {
        "worker_id": args.worker_id,
        "release_id": args.release_id,
        "image": args.image,
        "sbom_sha256": sha256_file(args.sbom),
        "provenance_sha256": sha256_file(args.provenance),
        "source_commit": args.source_commit,
        "status": args.status,
        "rollback_of": args.rollback_of,
    }
    _write_json(args.output, payload)


def _registry(records: list[Path], output: Path) -> None:
    releases = []
    for path in records:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise SystemExit(f"release record must be a JSON object: {path}")
        releases.append(payload)
    _write_json(output, {"schema_version": 1, "releases": releases})


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
            args.output,
        )
    elif args.command == "record":
        _record(args)
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
