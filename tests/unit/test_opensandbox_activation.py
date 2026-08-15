from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunter.security_tools import default_catalog
from vulnhunter.security_tools.executor import SecurityToolExecutionError, SecurityToolExecutor
from vulnhunter.security_tools.models import SecurityToolRequest, ToolProfile, ToolTargetKind
from vulnhunter.security_tools.opensandbox_activation import (
    ConfiguredOpenSandboxExecutionBackend,
    OpenSandboxActivationConfig,
    OpenSandboxActivationError,
    _opensandbox_permission_mode,
    build_opensandbox_backend_from_environment,
)


def _image(digest_character: str = "a") -> str:
    return "registry.example/vulnhunter/bandit@sha256:" + digest_character * 64


def _nuclei_image(digest_character: str = "b") -> str:
    return "registry.example/vulnhunter/nuclei@sha256:" + digest_character * 64


def test_activation_is_disabled_by_default() -> None:
    assert build_opensandbox_backend_from_environment({}) is None


def test_enabled_activation_requires_at_least_one_digest_pinned_worker() -> None:
    with pytest.raises(OpenSandboxActivationError, match="BANDIT_IMAGE"):
        OpenSandboxActivationConfig.from_environment({"VULNHUNTER_OPENSANDBOX_ENABLED": "true"})

    with pytest.raises(OpenSandboxActivationError, match="pinned by sha256 digest"):
        OpenSandboxActivationConfig.from_environment(
            {
                "VULNHUNTER_OPENSANDBOX_ENABLED": "true",
                "VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE": "registry.example/bandit:latest",
            }
        )

    with pytest.raises(OpenSandboxActivationError, match="pinned by sha256 digest"):
        OpenSandboxActivationConfig.from_environment(
            {
                "VULNHUNTER_OPENSANDBOX_ENABLED": "true",
                "VULNHUNTER_OPENSANDBOX_NUCLEI_IMAGE": "registry.example/nuclei:latest",
            }
        )


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


def test_enabled_activation_builds_non_root_bandit_runtime() -> None:
    backend = build_opensandbox_backend_from_environment(
        {
            "VULNHUNTER_OPENSANDBOX_ENABLED": "1",
            "VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE": _image(),
            "VULNHUNTER_OPENSANDBOX_DOMAIN": "127.0.0.1:8080",
        }
    )

    assert isinstance(backend, ConfiguredOpenSandboxExecutionBackend)
    assert backend.executable_for("bandit") == "/usr/local/bin/bandit"
    assert backend.executable_for("nuclei") is None
    runtime = backend.runtimes["bandit"]
    assert runtime.image == _image()
    assert runtime.uid == 65532
    assert runtime.gid == 65532
    assert runtime.memory == "512Mi"
    assert backend.connection.use_server_proxy is True


def test_enabled_activation_builds_exact_target_nuclei_runtime() -> None:
    backend = build_opensandbox_backend_from_environment(
        {
            "VULNHUNTER_OPENSANDBOX_ENABLED": "true",
            "VULNHUNTER_OPENSANDBOX_NUCLEI_IMAGE": _nuclei_image(),
            "VULNHUNTER_OPENSANDBOX_DOMAIN": "127.0.0.1:8080",
        }
    )

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


def test_executor_plans_backend_tool_without_host_binary(
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
        {
            "VULNHUNTER_OPENSANDBOX_ENABLED": "true",
            "VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE": _image(),
        }
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


def test_backend_runtime_absence_fails_without_host_fallback(tmp_path: Path) -> None:
    input_root = tmp_path / "inputs"
    output_root = tmp_path / "evidence"
    input_root.mkdir()
    target = input_root / "fixture.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    backend = build_opensandbox_backend_from_environment(
        {
            "VULNHUNTER_OPENSANDBOX_ENABLED": "true",
            "VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE": _image(),
        }
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