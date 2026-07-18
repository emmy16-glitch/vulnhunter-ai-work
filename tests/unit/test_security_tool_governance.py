import subprocess

import pytest

from vulnhunter.security_tools.adapters import ToolAdapterError, build_command_plan
from vulnhunter.security_tools.catalog import default_catalog
from vulnhunter.security_tools.executor import (
    SecurityToolExecutionError,
    SecurityToolExecutor,
)
from vulnhunter.security_tools.models import (
    SecurityToolRequest,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolProfile,
)


def _request(tmp_path, **updates):
    values = {
        "request_id": "request-01",
        "action_manifest_sha256": "a" * 64,
        "tool_id": "nmap",
        "profile": ToolProfile.DISCOVERY,
        "operation": "discover",
        "target": "192.168.100.0/24",
        "timeout_seconds": 60,
        "maximum_output_bytes": 100_000,
        "output_directory": tmp_path / "evidence",
    }
    values.update(updates)
    return SecurityToolRequest(**values)


def test_catalog_contains_free_assessment_stack():
    ids = {item.tool_id for item in default_catalog().list()}
    assert {
        "nmap",
        "httpx",
        "nuclei",
        "zap",
        "testssl",
        "trivy",
        "bearer",
        "amass",
        "ffuf",
        "sqlmap",
        "metasploit",
    } <= ids


def test_nmap_plan_is_shell_free_and_bounded(tmp_path):
    request = _request(tmp_path)
    plan = build_command_plan(
        request,
        executable="/usr/bin/nmap",
        catalog=default_catalog(),
    )
    assert plan.argv[0] == "/usr/bin/nmap"
    assert plan.argv[-1] == "192.168.100.0/24"
    assert "-oX" in plan.argv
    assert plan.requires_approval is True


def test_connector_only_tool_cannot_use_direct_adapter(tmp_path):
    request = _request(
        tmp_path,
        tool_id="metasploit",
        profile=ToolProfile.VALIDATION,
    )
    with pytest.raises(ToolAdapterError, match="dedicated connector"):
        build_command_plan(
            request,
            executable="/usr/bin/msfconsole",
            catalog=default_catalog(),
        )


def test_executor_is_disabled_by_default(tmp_path):
    executor = SecurityToolExecutor(
        catalog=default_catalog(),
        execution_enabled=False,
        approved_output_root=tmp_path,
    )
    request = _request(tmp_path)
    plan = build_command_plan(
        request,
        executable="/bin/echo",
        catalog=default_catalog(),
    )
    with pytest.raises(SecurityToolExecutionError, match="disabled by default"):
        executor.execute(
            plan,
            approval_consumed=True,
            execution_id="execution-01",
        )


def test_execution_cannot_be_enabled_without_authorization_gate(tmp_path):
    with pytest.raises(SecurityToolExecutionError, match="authorization gate"):
        SecurityToolExecutor(
            catalog=default_catalog(),
            execution_enabled=True,
            approved_output_root=tmp_path,
        )


def test_executor_rejects_plan_not_issued_by_same_executor(tmp_path):
    executor = SecurityToolExecutor(
        catalog=default_catalog(),
        execution_enabled=True,
        approved_output_root=tmp_path,
        execution_authorizer=lambda _plan, _execution_id: True,
    )
    request = _request(tmp_path)
    plan = build_command_plan(
        request,
        executable="/bin/echo",
        catalog=default_catalog(),
    )
    with pytest.raises(SecurityToolExecutionError, match="not issued"):
        executor.execute(
            plan,
            approval_consumed=True,
            execution_id="execution-01",
        )


def _enabled_executor_and_plan(
    tmp_path,
    monkeypatch,
    *,
    maximum_output_bytes=100_000,
    **request_updates,
):
    catalog = default_catalog()
    monkeypatch.setattr(
        catalog,
        "detect",
        lambda tool_id: ToolAvailability(
            tool_id=tool_id,
            available=True,
            usable=True,
            status=ToolAvailabilityStatus.READY,
            executable_path="/usr/bin/nmap",
            return_code=0,
        ),
    )
    executor = SecurityToolExecutor(
        catalog=catalog,
        execution_enabled=True,
        approved_output_root=tmp_path,
        execution_authorizer=lambda _plan, _execution_id: True,
    )
    plan = executor.plan(
        _request(
            tmp_path,
            maximum_output_bytes=maximum_output_bytes,
            **request_updates,
        )
    )
    return executor, plan


def test_executor_accepts_bounded_artifacts_without_buffering_pipes(tmp_path, monkeypatch):
    executor, plan = _enabled_executor_and_plan(tmp_path, monkeypatch)

    def bounded_run(argv, **kwargs):
        kwargs["stdout"].write(b"bounded stdout")
        kwargs["stderr"].write(b"bounded stderr")
        plan.output_files[0].write_text("<nmaprun></nmaprun>", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("vulnhunter.security_tools.executor.subprocess.run", bounded_run)
    result = executor.execute(
        plan,
        approval_consumed=True,
        execution_id="execution-bounded",
    )
    assert result.success is True
    assert result.stdout_preview == "bounded stdout"
    assert result.output_files == (str(plan.output_files[0].resolve()),)


def test_executor_redacts_captured_streams_before_persistence(tmp_path, monkeypatch):
    executor, plan = _enabled_executor_and_plan(
        tmp_path,
        monkeypatch,
        tool_id="sqlmap",
        profile=ToolProfile.VALIDATION,
        operation="validate",
        target="https://example.test/item?id=1",
    )
    bearer_secret = "test-bearer-token"
    password_secret = "test-password"

    def secret_run(argv, **kwargs):
        kwargs["stdout"].write(f"Authorization: Bearer {bearer_secret}\n".encode())
        kwargs["stderr"].write(f"password={password_secret}\n".encode())
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("vulnhunter.security_tools.executor.subprocess.run", secret_run)
    result = executor.execute(
        plan,
        approval_consumed=True,
        execution_id="execution-redacted",
    )

    assert plan.stdout_file is not None
    assert plan.stderr_file is not None
    stdout = plan.stdout_file.read_text(encoding="utf-8")
    stderr = plan.stderr_file.read_text(encoding="utf-8")
    assert bearer_secret not in stdout
    assert password_secret not in stderr
    assert "[REDACTED]" in stdout
    assert "[REDACTED]" in stderr
    assert bearer_secret not in result.stdout_preview
    assert password_secret not in result.stderr_preview


def test_executor_rejects_oversized_and_symlinked_tool_artifacts(tmp_path, monkeypatch):
    executor, plan = _enabled_executor_and_plan(
        tmp_path,
        monkeypatch,
        maximum_output_bytes=1_024,
    )

    def oversized_run(argv, **kwargs):
        plan.output_files[0].write_bytes(b"x" * 1_025)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("vulnhunter.security_tools.executor.subprocess.run", oversized_run)
    with pytest.raises(SecurityToolExecutionError, match="exceeds the configured output limit"):
        executor.execute(
            plan,
            approval_consumed=True,
            execution_id="execution-oversized",
        )

    executor, plan = _enabled_executor_and_plan(tmp_path / "symlink", monkeypatch)
    outside = tmp_path / "outside.xml"
    outside.write_text("outside", encoding="utf-8")

    def symlink_run(argv, **kwargs):
        plan.output_files[0].symlink_to(outside)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("vulnhunter.security_tools.executor.subprocess.run", symlink_run)
    with pytest.raises(SecurityToolExecutionError, match="escaped the approved output root"):
        executor.execute(
            plan,
            approval_consumed=True,
            execution_id="execution-symlink",
        )
