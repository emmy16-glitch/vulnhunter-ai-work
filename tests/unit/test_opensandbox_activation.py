from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnhunter.security_tools import default_catalog
from vulnhunter.security_tools.execution_backend import ExecutionBackendError
from vulnhunter.security_tools.executor import SecurityToolExecutionError, SecurityToolExecutor
from vulnhunter.security_tools.models import SecurityToolRequest, ToolProfile, ToolTargetKind
from vulnhunter.security_tools.opensandbox_activation import (
    ConfiguredOpenSandboxExecutionBackend,
    OpenSandboxActivationConfig,
    OpenSandboxActivationError,
    _opensandbox_permission_mode,
    build_opensandbox_backend_from_environment,
)
from vulnhunter.security_tools.opensandbox_supply_chain import canonical_json_bytes, public_key_id


def _image(digest_character: str = "a") -> str:
    return "registry.example/vulnhunter/bandit@sha256:" + digest_character * 64


def _nuclei_image(digest_character: str = "b") -> str:
    return "registry.example/vulnhunter/nuclei@sha256:" + digest_character * 64


def _signed_release_environment(
    tmp_path: Path,
    *,
    bandit_image: str | None = None,
    nuclei_image: str | None = None,
    status: str = "approved",
) -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    releases = []
    for worker_id, image, character in (
        ("bandit", bandit_image, "c"),
        ("nuclei", nuclei_image, "d"),
    ):
        if image is None:
            continue
        releases.append(
            {
                "worker_id": worker_id,
                "release_id": f"{worker_id}-release-1",
                "image": image,
                "sbom_sha256": character * 64,
                "provenance_sha256": ("e" if worker_id == "bandit" else "f") * 64,
                "source_commit": "1" * 40,
                "status": status,
                "rollback_of": None,
            }
        )
    registry_payload = {"schema_version": 1, "releases": releases}
    registry = tmp_path / "workers.json"
    signature = tmp_path / "workers.sig.json"
    public_key = tmp_path / "workers.pub.pem"
    registry.write_text(json.dumps(registry_payload), encoding="utf-8")
    signature.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "algorithm": "ed25519",
                "key_id": public_key_id(public_bytes),
                "signature": base64.b64encode(
                    private_key.sign(canonical_json_bytes(registry_payload))
                ).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )
    public_key.write_bytes(public_bytes)
    environment = {
        "VULNHUNTER_OPENSANDBOX_ENABLED": "true",
        "VULNHUNTER_OPENSANDBOX_RELEASE_REGISTRY_FILE": str(registry),
        "VULNHUNTER_OPENSANDBOX_RELEASE_SIGNATURE_FILE": str(signature),
        "VULNHUNTER_OPENSANDBOX_RELEASE_PUBLIC_KEY_FILE": str(public_key),
    }
    if bandit_image is not None:
        environment["VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE"] = bandit_image
    if nuclei_image is not None:
        environment["VULNHUNTER_OPENSANDBOX_NUCLEI_IMAGE"] = nuclei_image
    return environment


def test_activation_is_disabled_by_default() -> None:
    assert build_opensandbox_backend_from_environment({}) is None


def test_enabled_activation_requires_worker_and_signed_release_files() -> None:
    with pytest.raises(OpenSandboxActivationError, match="BANDIT_IMAGE"):
        OpenSandboxActivationConfig.from_environment({"VULNHUNTER_OPENSANDBOX_ENABLED": "true"})

    with pytest.raises(OpenSandboxActivationError, match="signed OpenSandbox worker releases"):
        OpenSandboxActivationConfig.from_environment(
            {
                "VULNHUNTER_OPENSANDBOX_ENABLED": "true",
                "VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE": _image(),
            }
        )


def test_mutable_worker_tags_remain_rejected(tmp_path: Path) -> None:
    environment = _signed_release_environment(tmp_path, bandit_image=_image())
    environment["VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE"] = "registry.example/bandit:latest"
    with pytest.raises(OpenSandboxActivationError, match="pinned by sha256 digest"):
        OpenSandboxActivationConfig.from_environment(environment)


def test_remote_http_control_plane_is_rejected() -> None:
    with pytest.raises(OpenSandboxActivationError, match="must use https"):
        OpenSandboxActivationConfig.from_environment(
            {
                "VULNHUNTER_OPENSANDBOX_DOMAIN": "sandbox.internal.example:8080",
                "VULNHUNTER_OPENSANDBOX_PROTOCOL": "http",
            }
        )


def test_python_permission_modes_are_encoded_for_opensandbox() -> None:
    assert _opensandbox_permission_mode(0o755) == 755
    assert _opensandbox_permission_mode(0o733) == 733
    assert _opensandbox_permission_mode(0o555) == 555
    assert _opensandbox_permission_mode(0o444) == 444
    assert _opensandbox_permission_mode(0o777) == 777

    with pytest.raises(OpenSandboxActivationError, match="POSIX range"):
        _opensandbox_permission_mode(0o10000)


def test_enabled_activation_builds_signed_non_root_bandit_runtime(tmp_path: Path) -> None:
    environment = _signed_release_environment(tmp_path, bandit_image=_image())
    environment["VULNHUNTER_OPENSANDBOX_DOMAIN"] = "127.0.0.1:8080"
    backend = build_opensandbox_backend_from_environment(environment)

    assert isinstance(backend, ConfiguredOpenSandboxExecutionBackend)
    assert backend.executable_for("bandit") == "/usr/local/bin/bandit"
    assert backend.executable_for("nuclei") is None
    runtime = backend.runtimes["bandit"]
    assert runtime.image == _image()
    assert runtime.uid == 65532
    assert runtime.gid == 65532
    assert runtime.memory == "512Mi"
    assert backend.connection.use_server_proxy is True
    assert backend.approved_releases["bandit"].release_id == "bandit-release-1"
    assert backend.release_key_id.startswith("sha256:")


def test_enabled_activation_builds_signed_exact_target_nuclei_runtime(tmp_path: Path) -> None:
    environment = _signed_release_environment(tmp_path, nuclei_image=_nuclei_image())
    environment["VULNHUNTER_OPENSANDBOX_DOMAIN"] = "127.0.0.1:8080"
    backend = build_opensandbox_backend_from_environment(environment)

    assert isinstance(backend, ConfiguredOpenSandboxExecutionBackend)
    assert backend.executable_for("bandit") is None
    assert backend.executable_for("nuclei") == "/usr/local/bin/nuclei"
    assert backend.nuclei_runtime is not None
    assert backend.nuclei_runtime.image == _nuclei_image()
    assert backend.nuclei_runtime.uid == 65532
    assert backend.nuclei_runtime.gid == 65532
    assert backend.nuclei_runtime.memory == "1Gi"
    assert backend.nuclei_runtime.template_manifest_sha256 == (
        "088f533aaa631f178bde29c3589d286b3bb136f839772a39d9276f16b545d35c"
    )
    assert backend.approved_releases["nuclei"].release_id == "nuclei-release-1"


def test_revoked_signed_worker_fails_activation(tmp_path: Path) -> None:
    environment = _signed_release_environment(
        tmp_path,
        bandit_image=_image(),
        status="revoked",
    )
    with pytest.raises(OpenSandboxActivationError, match="has no approved signed release"):
        build_opensandbox_backend_from_environment(environment)


def test_unlisted_worker_digest_fails_activation(tmp_path: Path) -> None:
    environment = _signed_release_environment(tmp_path, bandit_image=_image())
    environment["VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE"] = _image("f")
    with pytest.raises(OpenSandboxActivationError, match="absent from the signed"):
        build_opensandbox_backend_from_environment(environment)


def test_executor_plan_binds_signed_release_without_host_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root = tmp_path / "inputs"
    output_root = tmp_path / "evidence"
    input_root.mkdir()
    target = input_root / "fixture.py"
    target.write_text("import subprocess\nsubprocess.run('id', shell=True)\n", encoding="utf-8")

    catalog = default_catalog()

    def fail_if_host_detection_runs(tool_id: str):
        raise AssertionError(f"host detection must not run for backend tool: {tool_id}")

    monkeypatch.setattr(catalog, "detect", fail_if_host_detection_runs)
    backend = build_opensandbox_backend_from_environment(
        _signed_release_environment(tmp_path, bandit_image=_image())
    )
    assert backend is not None
    executor = SecurityToolExecutor(
        catalog=catalog,
        approved_output_root=output_root,
        approved_input_roots=(input_root,),
        execution_backend=backend,
    )
    request = SecurityToolRequest(
        request_id="bandit-fixture",
        action_manifest_sha256="0" * 64,
        tool_id="bandit",
        profile=ToolProfile.SAFE_ASSESSMENT,
        operation="scan",
        target=str(target),
        target_kind=ToolTargetKind.LOCAL_PATH,
        timeout_seconds=30,
        maximum_output_bytes=100_000,
        output_directory=output_root,
    )

    plan = executor.plan(request)

    assert plan.executable == "/usr/local/bin/bandit"
    assert plan.argv[0] == "/usr/local/bin/bandit"
    assert plan.target == str(target.resolve())
    assert plan.runtime_image == _image()
    assert plan.runtime_release_id == "bandit-release-1"
    assert plan.runtime_sbom_sha256 == "c" * 64
    assert plan.runtime_provenance_sha256 == "e" * 64
    assert plan.runtime_source_commit == "1" * 40
    assert plan.runtime_release_registry_sha256 == backend.release_registry_sha256
    assert plan.runtime_release_key_id == backend.release_key_id

    tampered = plan.model_copy(update={"runtime_sbom_sha256": "9" * 64})
    with pytest.raises(ExecutionBackendError, match="supply-chain identity changed"):
        backend.execute(tampered, approved_input_roots=(input_root,))


def test_backend_runtime_absence_fails_without_host_fallback(tmp_path: Path) -> None:
    input_root = tmp_path / "inputs"
    output_root = tmp_path / "evidence"
    input_root.mkdir()
    target = input_root / "fixture.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    backend = build_opensandbox_backend_from_environment(
        _signed_release_environment(tmp_path, bandit_image=_image())
    )
    assert backend is not None
    executor = SecurityToolExecutor(
        catalog=default_catalog(),
        approved_output_root=output_root,
        approved_input_roots=(input_root,),
        execution_backend=backend,
    )
    request = SecurityToolRequest(
        request_id="capa-fixture",
        action_manifest_sha256="0" * 64,
        tool_id="capa",
        profile=ToolProfile.SAFE_ASSESSMENT,
        operation="scan",
        target=str(target),
        target_kind=ToolTargetKind.BINARY_FILE,
        output_directory=output_root,
    )

    with pytest.raises(SecurityToolExecutionError, match="does not provide a runtime"):
        executor.plan(request)
