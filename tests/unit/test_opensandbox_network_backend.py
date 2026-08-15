from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunter.security_tools import default_catalog
from vulnhunter.security_tools.execution_backend import ExecutionBackendError, OpenSandboxConnection
from vulnhunter.security_tools.executor import SecurityToolExecutor
from vulnhunter.security_tools.models import SecurityToolRequest, ToolProfile, ToolTargetKind
from vulnhunter.security_tools.opensandbox_network_backend import (
    NucleiOpenSandboxRuntimeSpec,
    OpenSandboxNucleiExecutionBackend,
    _bind_network_target,
)

_IMAGE = "registry.example/vulnhunter/nuclei@sha256:" + "a" * 64
_MANIFEST = "b" * 64


def _runtime() -> NucleiOpenSandboxRuntimeSpec:
    return NucleiOpenSandboxRuntimeSpec(
        image=_IMAGE,
        template_manifest_sha256=_MANIFEST,
    )


def test_hostname_binding_pins_approved_ipv4_and_preserves_http_identity() -> None:
    binding = _bind_network_target(
        "https://Example.TEST:8443/account?q=1",
        approved_ip="10.20.30.41",
        resolver=lambda _host, _port: ("10.20.30.42", "10.20.30.41"),
    )

    assert binding.hostname == "example.test"
    assert binding.ip_address == "10.20.30.41"
    assert binding.port == 8443
    assert binding.connect_url == "https://10.20.30.41:8443/account?q=1"
    assert binding.host_header == "example.test:8443"
    assert binding.tls_server_name == "example.test"


def test_approved_ip_must_be_in_current_dns_result() -> None:
    with pytest.raises(ExecutionBackendError, match="not present"):
        _bind_network_target(
            "https://example.test/",
            approved_ip="10.20.30.99",
            resolver=lambda _host, _port: ("10.20.30.41",),
        )


def test_executor_fingerprints_final_nuclei_runtime_and_network_binding(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    backend = OpenSandboxNucleiExecutionBackend(
        runtime=_runtime(),
        connection=OpenSandboxConnection(domain="127.0.0.1:8080", use_server_proxy=True),
        resolver=lambda _host, _port: ("10.20.30.41",),
    )
    executor = SecurityToolExecutor(
        catalog=default_catalog(),
        approved_output_root=evidence_root,
        execution_backend=backend,
    )
    request = SecurityToolRequest(
        request_id="nuclei-network-plan",
        action_manifest_sha256="0" * 64,
        tool_id="nuclei",
        profile=ToolProfile.SAFE_ASSESSMENT,
        operation="scan",
        target="https://example.test:8443/account?q=1",
        target_kind=ToolTargetKind.NETWORK,
        timeout_seconds=30,
        maximum_output_bytes=250_000,
        output_directory=evidence_root,
        parameters={"scan_profile": "passive", "approved_ip": "10.20.30.41"},
    )

    plan = executor.plan(request)

    assert plan.runtime_image == _IMAGE
    assert plan.template_manifest_sha256 == _MANIFEST
    assert plan.network_binding is not None
    assert plan.network_binding.ip_address == "10.20.30.41"
    assert plan.network_binding.port == 8443
    assert "https://10.20.30.41:8443/account?q=1" in plan.argv
    assert "-templates" in plan.argv
    assert "/opt/vulnhunter/templates" in plan.argv
    assert "-disable-redirects" in plan.argv
    assert "-no-httpx" in plan.argv
    assert "-restrict-local-network-access" not in plan.argv
    assert "-disable-unsigned-templates" not in plan.argv
    assert "Host: example.test:8443" in plan.argv
    assert "-sni" in plan.argv
    assert "example.test" in plan.argv
    assert plan.fingerprint() != request.action_manifest_sha256


def test_network_backend_refuses_dns_change_before_sandbox_creation(tmp_path: Path) -> None:
    current = {"addresses": ("10.20.30.41",)}

    class FailIfCreatedSdk:
        def create(self, **_kwargs):
            raise AssertionError("sandbox must not be created after DNS binding changes")

    backend = OpenSandboxNucleiExecutionBackend(
        runtime=_runtime(),
        resolver=lambda _host, _port: current["addresses"],
        sdk=FailIfCreatedSdk(),
    )
    executor = SecurityToolExecutor(
        catalog=default_catalog(),
        approved_output_root=tmp_path / "evidence",
        execution_backend=backend,
    )
    request = SecurityToolRequest(
        request_id="nuclei-dns-rebind",
        action_manifest_sha256="0" * 64,
        tool_id="nuclei",
        profile=ToolProfile.SAFE_ASSESSMENT,
        operation="scan",
        target="http://example.test:8011/",
        target_kind=ToolTargetKind.NETWORK,
        output_directory=tmp_path / "evidence",
        parameters={"scan_profile": "passive"},
    )
    plan = executor.plan(request)
    current["addresses"] = ("10.20.30.42",)

    with pytest.raises(ExecutionBackendError, match="DNS changed"):
        backend.execute(plan, approved_input_roots=())


def test_first_network_worker_rejects_non_passive_nuclei_profile(tmp_path: Path) -> None:
    backend = OpenSandboxNucleiExecutionBackend(
        runtime=_runtime(),
        resolver=lambda _host, _port: ("10.20.30.41",),
    )
    executor = SecurityToolExecutor(
        catalog=default_catalog(),
        approved_output_root=tmp_path / "evidence",
        execution_backend=backend,
    )
    request = SecurityToolRequest(
        request_id="nuclei-active-denied",
        action_manifest_sha256="0" * 64,
        tool_id="nuclei",
        profile=ToolProfile.ACTIVE_ASSESSMENT,
        operation="scan",
        target="http://example.test/",
        target_kind=ToolTargetKind.NETWORK,
        output_directory=tmp_path / "evidence",
        parameters={"scan_profile": "standard", "tags": ["misconfig"]},
    )

    with pytest.raises(ExecutionBackendError, match="passive scans only"):
        plan = executor.plan(request)
        backend.bind_plan(plan, request)
