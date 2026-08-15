from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnhunter.actions.models import ActionClass
from vulnhunter.security_tools.execution_backend import (
    ExecutionBackendError,
    OpenSandboxExecutionBackend,
    OpenSandboxRuntimeSpec,
)
from vulnhunter.security_tools.models import CommandPlan, ToolTargetKind


class FakeSandboxSdk:
    def __init__(self, *, fail_run: bool = False) -> None:
        self.files: dict[str, bytes] = {}
        self.directories: list[tuple[str, int]] = []
        self.created = False
        self.destroyed = False
        self.fail_run = fail_run
        self.payload: dict[str, object] | None = None

    def create(self, *, runtime, lifetime_seconds: int, metadata: dict[str, str]):
        self.created = True
        self.runtime = runtime
        self.lifetime_seconds = lifetime_seconds
        self.metadata = metadata
        return self

    def make_directory(self, sandbox: object, path: str, *, mode: int) -> None:
        self.directories.append((path, mode))

    def write_file(
        self,
        sandbox: object,
        path: str,
        data: str | bytes,
        *,
        mode: int,
    ) -> None:
        self.files[path] = data.encode() if isinstance(data, str) else data

    def run_fixed_runner(
        self,
        sandbox: object,
        *,
        runtime,
        timeout_seconds: int,
    ) -> int:
        if self.fail_run:
            raise RuntimeError("simulated sandbox transport failure")
        self.payload = json.loads(
            self.files["/tmp/vulnhunter/control/plan.json"].decode("utf-8")
        )
        outputs = self.payload["outputs"]
        artifacts = []
        for output in outputs:
            data = b'{"finding":"bounded"}'
            self.files[output] = data
            artifacts.append({"path": output, "size": len(data)})
        self.files["/tmp/vulnhunter/control/stdout.bin"] = b"sandbox stdout"
        self.files["/tmp/vulnhunter/control/stderr.bin"] = b""
        status = {
            "return_code": 0,
            "timed_out": False,
            "runner_error": None,
            "capture_overflow": False,
            "artifact_error": None,
            "artifacts": artifacts,
        }
        self.files["/tmp/vulnhunter/control/status.json"] = json.dumps(status).encode()
        return 0

    def read_bytes(self, sandbox: object, path: str) -> bytes:
        return self.files[path]

    def destroy(self, sandbox: object) -> None:
        self.destroyed = True


def _runtime() -> OpenSandboxRuntimeSpec:
    return OpenSandboxRuntimeSpec(
        image="registry.invalid/vulnhunter/static@sha256:" + "a" * 64,
        executable="/opt/vulnhunter/bin/scanner",
    )


def _plan(tmp_path: Path, *, target_kind: ToolTargetKind) -> CommandPlan:
    input_root = tmp_path / "inputs"
    output_root = tmp_path / "evidence"
    input_root.mkdir()
    output_root.mkdir()
    target = input_root / "sample;touch-owned.apk"
    target.write_bytes(b"APK fixture")
    output = output_root / "scan.json"
    return CommandPlan(
        request_id="request-1",
        tool_id="fixture-scanner",
        executable="/host/bin/scanner",
        argv=("/host/bin/scanner", "--output", str(output), str(target)),
        target=str(target),
        target_kind=target_kind,
        output_files=(output,),
        timeout_seconds=30,
        maximum_output_bytes=4096,
        working_directory=output_root,
        action_manifest_sha256="0" * 64,
        requires_approval=False,
        requires_isolation=True,
        action_class=ActionClass.READ_ONLY,
    )


def test_runtime_requires_digest_pinned_image() -> None:
    with pytest.raises(ValueError, match="pinned by sha256 digest"):
        OpenSandboxRuntimeSpec(
            image="registry.invalid/vulnhunter/static:latest",
            executable="/opt/vulnhunter/bin/scanner",
        )


def test_backend_keeps_authorized_argv_out_of_shell_command(tmp_path: Path) -> None:
    sdk = FakeSandboxSdk()
    plan = _plan(tmp_path, target_kind=ToolTargetKind.APK_FILE)
    backend = OpenSandboxExecutionBackend(
        runtimes={"fixture-scanner": _runtime()},
        sdk=sdk,
    )

    result = backend.execute(
        plan,
        approved_input_roots=(tmp_path / "inputs",),
    )

    assert result.return_code == 0
    assert result.stdout == b"sandbox stdout"
    assert result.artifacts[0].host_path == plan.output_files[0]
    assert sdk.destroyed is True
    assert sdk.payload is not None
    argv = sdk.payload["argv"]
    assert argv[0] == "/opt/vulnhunter/bin/scanner"
    assert str(plan.target) not in argv
    assert ";touch-owned" not in json.dumps(sdk.payload)
    assert argv[-1].startswith("/tmp/vulnhunter/input/")


def test_backend_blocks_network_targets_before_sandbox_creation(tmp_path: Path) -> None:
    sdk = FakeSandboxSdk()
    plan = _plan(tmp_path, target_kind=ToolTargetKind.NETWORK).model_copy(
        update={"target": "127.0.0.1"}
    )
    backend = OpenSandboxExecutionBackend(
        runtimes={"fixture-scanner": _runtime()},
        sdk=sdk,
    )

    with pytest.raises(ExecutionBackendError, match="IP/CIDR boundary"):
        backend.execute(plan, approved_input_roots=(tmp_path / "inputs",))

    assert sdk.created is False


def test_backend_destroys_sandbox_when_execution_transport_fails(tmp_path: Path) -> None:
    sdk = FakeSandboxSdk(fail_run=True)
    plan = _plan(tmp_path, target_kind=ToolTargetKind.BINARY_FILE)
    backend = OpenSandboxExecutionBackend(
        runtimes={"fixture-scanner": _runtime()},
        sdk=sdk,
    )

    with pytest.raises(ExecutionBackendError, match="failed closed"):
        backend.execute(plan, approved_input_roots=(tmp_path / "inputs",))

    assert sdk.created is True
    assert sdk.destroyed is True
