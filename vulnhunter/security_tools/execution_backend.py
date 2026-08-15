"""Fail-closed OpenSandbox backend for governed security-tool command plans."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Literal, Protocol

from vulnhunter.security_tools.models import CommandPlan, ToolTargetKind

_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_ROOT = "/tmp/vulnhunter"
_CONTROL = f"{_ROOT}/control"
_INPUT = f"{_ROOT}/input"
_WORK = f"{_ROOT}/work"
_RUNNER = f"{_CONTROL}/runner.py"
_PLAN = f"{_CONTROL}/plan.json"
_STATUS = f"{_CONTROL}/status.json"
_STDOUT = f"{_CONTROL}/stdout.bin"
_STDERR = f"{_CONTROL}/stderr.bin"
_DIRECTORY_OUTPUT_TOOLS = frozenset({"apktool", "jadx"})

# The SDK command endpoint accepts shell text. To preserve VulnHunter's argv-only
# boundary, the only command sent to it is the literal runner command below.
# The authorized argv is written as JSON and this runner invokes it shell=False.
_RUNNER_SOURCE = r"""
import json
import os
import signal
import stat
import subprocess
from pathlib import Path

control = Path("/tmp/vulnhunter/control")
payload = json.loads((control / "plan.json").read_text(encoding="utf-8"))
stdout_path = control / "stdout.bin"
stderr_path = control / "stderr.bin"
status_path = control / "status.json"
work = Path(payload["working_directory"])
work.mkdir(parents=True, exist_ok=True)

environment = {
    "PATH": payload["environment"]["PATH"],
    "HOME": payload["environment"]["HOME"],
    "LANG": payload["environment"]["LANG"],
    "LC_ALL": payload["environment"]["LC_ALL"],
}
timed_out = False
return_code = 125
runner_error = None

try:
    with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
        process = subprocess.Popen(
            payload["argv"],
            cwd=work,
            env=environment,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=int(payload["timeout_seconds"]))
        except subprocess.TimeoutExpired:
            timed_out = True
            return_code = 124
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
except (OSError, subprocess.SubprocessError, ValueError) as exc:
    runner_error = type(exc).__name__

maximum = int(payload["maximum_output_bytes"])
capture_overflow = any(
    path.exists() and path.stat().st_size > maximum
    for path in (stdout_path, stderr_path)
)
for path in (stdout_path, stderr_path):
    if not path.exists():
        path.touch()

artifact_error = None
artifacts = []
for output in payload["outputs"]:
    candidate = Path(output)
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        continue
    if stat.S_ISLNK(metadata.st_mode):
        artifact_error = "sandbox output artifact is a symbolic link"
        break
    if not stat.S_ISREG(metadata.st_mode):
        artifact_error = "sandbox output artifact is not a regular file"
        break
    if metadata.st_size > maximum:
        artifact_error = "sandbox output artifact exceeded the configured output limit"
        break
    artifacts.append({"path": output, "size": metadata.st_size})

status = {
    "return_code": return_code,
    "timed_out": timed_out,
    "runner_error": runner_error,
    "capture_overflow": capture_overflow,
    "artifact_error": artifact_error,
    "artifacts": artifacts,
}
temporary = status_path.with_suffix(".part")
temporary.write_text(json.dumps(status, sort_keys=True, separators=(",", ":")), encoding="utf-8")
os.replace(temporary, status_path)
"""


class ExecutionBackendError(RuntimeError):
    """Raised when a backend cannot preserve the execution contract."""


@dataclass(frozen=True)
class BackendArtifact:
    host_path: Path
    data: bytes


@dataclass(frozen=True)
class BackendExecutionResult:
    return_code: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    artifacts: tuple[BackendArtifact, ...] = ()


class SecurityToolExecutionBackend(Protocol):
    @property
    def isolated(self) -> bool: ...

    def execute(
        self,
        plan: CommandPlan,
        *,
        approved_input_roots: tuple[Path, ...],
    ) -> BackendExecutionResult: ...


@dataclass(frozen=True)
class OpenSandboxRuntimeSpec:
    """One non-root, digest-pinned OpenSandbox worker image."""

    image: str
    executable: str
    cpu: str = "1"
    memory: str = "2Gi"
    uid: int = 65532
    gid: int = 65532
    path: str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    def __post_init__(self) -> None:
        if _IMAGE_DIGEST.fullmatch(self.image) is None:
            raise ValueError("OpenSandbox worker image must be pinned by sha256 digest")
        if not self.executable.startswith("/") or "\x00" in self.executable:
            raise ValueError("OpenSandbox worker executable must be an absolute path")
        if self.uid <= 0 or self.gid <= 0:
            raise ValueError("OpenSandbox tool execution must use a non-root uid and gid")
        if not self.cpu or not self.memory or not self.path:
            raise ValueError("OpenSandbox runtime resource fields must not be empty")


@dataclass(frozen=True)
class OpenSandboxConnection:
    """Non-secret control-plane settings; API key remains environment-only."""

    domain: str | None = None
    protocol: Literal["http", "https"] = "http"
    use_server_proxy: bool = False
    request_timeout_seconds: int = 30
    ready_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if self.request_timeout_seconds <= 0 or self.ready_timeout_seconds <= 0:
            raise ValueError("OpenSandbox timeouts must be positive")


class _SandboxSdk(Protocol):
    """Small seam that keeps the optional third-party SDK out of unit tests."""

    def create(
        self,
        *,
        runtime: OpenSandboxRuntimeSpec,
        lifetime_seconds: int,
        metadata: dict[str, str],
    ) -> object: ...

    def make_directory(self, sandbox: object, path: str, *, mode: int) -> None: ...

    def write_file(
        self,
        sandbox: object,
        path: str,
        data: str | bytes,
        *,
        mode: int,
    ) -> None: ...

    def run_fixed_runner(
        self,
        sandbox: object,
        *,
        runtime: OpenSandboxRuntimeSpec,
        timeout_seconds: int,
    ) -> int | None: ...

    def read_bytes(self, sandbox: object, path: str) -> bytes: ...

    def destroy(self, sandbox: object) -> None: ...


class _OpenSandboxSdkV015:
    """Adapter for the OpenSandbox Python 0.1.15 surface."""

    def __init__(self, connection: OpenSandboxConnection) -> None:
        self.connection = connection

    def create(
        self,
        *,
        runtime: OpenSandboxRuntimeSpec,
        lifetime_seconds: int,
        metadata: dict[str, str],
    ) -> object:
        try:
            from opensandbox import SandboxSync
            from opensandbox.config import ConnectionConfigSync
            from opensandbox.models.sandboxes import NetworkPolicy
        except ImportError as exc:
            raise ExecutionBackendError(
                "OpenSandbox support is not installed; install vulnhunter-ai[opensandbox]"
            ) from exc

        config = ConnectionConfigSync(
            domain=self.connection.domain,
            protocol=self.connection.protocol,
            request_timeout=timedelta(seconds=self.connection.request_timeout_seconds),
            use_server_proxy=self.connection.use_server_proxy,
        )
        return SandboxSync.create(
            runtime.image,
            connection_config=config,
            timeout=timedelta(seconds=lifetime_seconds),
            ready_timeout=timedelta(seconds=self.connection.ready_timeout_seconds),
            resource={"cpu": runtime.cpu, "memory": runtime.memory},
            network_policy=NetworkPolicy(defaultAction="deny", egress=[]),
            metadata=metadata,
            env={},
        )

    def make_directory(self, sandbox: object, path: str, *, mode: int) -> None:
        try:
            from opensandbox.models.filesystem import WriteEntry
        except ImportError as exc:
            raise ExecutionBackendError("OpenSandbox filesystem models are unavailable") from exc
        sandbox.files.create_directories([WriteEntry(path=path, mode=mode)])

    def write_file(
        self,
        sandbox: object,
        path: str,
        data: str | bytes,
        *,
        mode: int,
    ) -> None:
        sandbox.files.write_file(path, data, mode=mode)

    def run_fixed_runner(
        self,
        sandbox: object,
        *,
        runtime: OpenSandboxRuntimeSpec,
        timeout_seconds: int,
    ) -> int | None:
        try:
            from opensandbox.models.execd import RunCommandOpts
        except ImportError as exc:
            raise ExecutionBackendError("OpenSandbox command models are unavailable") from exc
        execution = sandbox.commands.run(
            f"python3 {_RUNNER}",
            opts=RunCommandOpts(
                working_directory=_ROOT,
                timeout=timedelta(seconds=timeout_seconds),
                uid=runtime.uid,
                gid=runtime.gid,
            ),
        )
        return execution.exit_code

    def read_bytes(self, sandbox: object, path: str) -> bytes:
        return sandbox.files.read_bytes(path)

    def destroy(self, sandbox: object) -> None:
        sandbox.destroy()


class OpenSandboxExecutionBackend:
    """Disposable, network-denied execution for offline file-backed workloads."""

    isolated = True

    def __init__(
        self,
        *,
        runtimes: Mapping[str, OpenSandboxRuntimeSpec],
        connection: OpenSandboxConnection | None = None,
        maximum_input_bytes: int = 100_000_000,
        sdk: _SandboxSdk | None = None,
    ) -> None:
        if maximum_input_bytes < 1024:
            raise ValueError("maximum_input_bytes must be at least 1024")
        self.runtimes = dict(runtimes)
        self.connection = connection or OpenSandboxConnection()
        self.maximum_input_bytes = maximum_input_bytes
        self._sdk: _SandboxSdk = sdk or _OpenSandboxSdkV015(self.connection)

    def execute(
        self,
        plan: CommandPlan,
        *,
        approved_input_roots: tuple[Path, ...],
    ) -> BackendExecutionResult:
        self._check_supported(plan)
        runtime = self.runtimes.get(plan.tool_id)
        if runtime is None:
            raise ExecutionBackendError(
                f"No digest-pinned OpenSandbox runtime is registered for {plan.tool_id}"
            )
        if plan.target is None:
            raise ExecutionBackendError("OpenSandbox execution requires a bound target")

        target = _validated_input_file(plan.target, approved_input_roots)
        target_data = _read_bounded_file(target, maximum_bytes=self.maximum_input_bytes)
        sandbox_target = f"{_INPUT}/{_safe_filename(target.name)}"
        output_mapping = _output_mapping(plan)
        argv = _rewrite_argv(
            plan,
            runtime=runtime,
            target=target,
            sandbox_target=sandbox_target,
            output_mapping=output_mapping,
        )
        payload = {
            "argv": list(argv),
            "timeout_seconds": plan.timeout_seconds,
            "maximum_output_bytes": plan.maximum_output_bytes,
            "working_directory": _WORK,
            "outputs": list(output_mapping.values()),
            "environment": {
                "PATH": runtime.path,
                "HOME": "/tmp",
                "LANG": "C",
                "LC_ALL": "C",
            },
        }

        sandbox = None
        result = None
        failure: ExecutionBackendError | None = None
        try:
            sandbox = self._sdk.create(
                runtime=runtime,
                lifetime_seconds=min(max(plan.timeout_seconds + 90, 120), 86490),
                metadata={
                    "project": "vulnhunter",
                    "tool": plan.tool_id,
                    "request": plan.request_id,
                },
            )
            self._prepare(
                sandbox,
                target_data=target_data,
                sandbox_target=sandbox_target,
                payload=payload,
            )
            wrapper_exit = self._sdk.run_fixed_runner(
                sandbox,
                runtime=runtime,
                timeout_seconds=min(plan.timeout_seconds + 30, 86430),
            )
            if wrapper_exit not in {0, None}:
                raise ExecutionBackendError(
                    "OpenSandbox fixed runner failed before producing trusted evidence"
                )
            result = self._collect(
                sandbox,
                plan=plan,
                output_mapping=output_mapping,
            )
        except ExecutionBackendError as exc:
            failure = exc
        except Exception as exc:
            failure = ExecutionBackendError(
                f"OpenSandbox execution failed closed: {type(exc).__name__}"
            )
            failure.__cause__ = exc
        finally:
            if sandbox is not None:
                try:
                    self._sdk.destroy(sandbox)
                except Exception as exc:
                    if failure is None:
                        raise ExecutionBackendError(
                            f"OpenSandbox destruction failed: {type(exc).__name__}"
                        ) from exc

        if failure is not None:
            raise failure
        if result is None:
            raise ExecutionBackendError("OpenSandbox execution produced no result")
        return result

    @staticmethod
    def _check_supported(plan: CommandPlan) -> None:
        if plan.target_kind in {
            ToolTargetKind.NETWORK,
            ToolTargetKind.CONTAINER_IMAGE,
            ToolTargetKind.ANDROID_DEVICE,
        }:
            raise ExecutionBackendError(
                "OpenSandbox network/device execution is disabled until VulnHunter can "
                "enforce its exact authorized IP/CIDR boundary inside the sandbox"
            )
        if plan.tool_id in _DIRECTORY_OUTPUT_TOOLS:
            raise ExecutionBackendError(
                f"OpenSandbox directory artifact transfer is not enabled for {plan.tool_id}"
            )

    def _prepare(
        self,
        sandbox: object,
        *,
        target_data: bytes,
        sandbox_target: str,
        payload: dict[str, object],
    ) -> None:
        for path, mode in (
            (_ROOT, 0o755),
            (_CONTROL, 0o755),
            (_INPUT, 0o755),
            (_WORK, 0o777),
            (f"{_WORK}/output", 0o777),
        ):
            self._sdk.make_directory(sandbox, path, mode=mode)
        self._sdk.write_file(sandbox, _RUNNER, _RUNNER_SOURCE, mode=0o555)
        self._sdk.write_file(
            sandbox,
            _PLAN,
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            mode=0o444,
        )
        self._sdk.write_file(sandbox, sandbox_target, target_data, mode=0o444)

    def _collect(
        self,
        sandbox: object,
        *,
        plan: CommandPlan,
        output_mapping: Mapping[Path, str],
    ) -> BackendExecutionResult:
        status = _parse_status(self._sdk.read_bytes(sandbox, _STATUS))
        if status.get("runner_error"):
            raise ExecutionBackendError(
                f"OpenSandbox fixed runner failed closed: {status['runner_error']}"
            )
        if status.get("capture_overflow") is True:
            raise ExecutionBackendError(
                "OpenSandbox tool stdout/stderr exceeded the configured output limit"
            )
        if status.get("artifact_error"):
            raise ExecutionBackendError(str(status["artifact_error"]))

        stdout = _bounded_sandbox_read(
            self._sdk, sandbox, _STDOUT, plan.maximum_output_bytes, "stdout"
        )
        stderr = _bounded_sandbox_read(
            self._sdk, sandbox, _STDERR, plan.maximum_output_bytes, "stderr"
        )
        artifacts = _collect_artifacts(
            self._sdk,
            sandbox,
            status=status,
            output_mapping=output_mapping,
            maximum_bytes=plan.maximum_output_bytes,
        )
        return BackendExecutionResult(
            return_code=_status_int(status, "return_code"),
            timed_out=bool(status.get("timed_out", False)),
            stdout=stdout,
            stderr=stderr,
            artifacts=artifacts,
        )


def _validated_input_file(target: str, approved_roots: tuple[Path, ...]) -> Path:
    if not approved_roots:
        raise ExecutionBackendError("OpenSandbox execution requires an approved input root")
    candidate = Path(target).expanduser()
    if candidate.is_symlink():
        raise ExecutionBackendError("OpenSandbox input target must not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ExecutionBackendError("OpenSandbox input target is unavailable") from exc
    if not resolved.is_file():
        raise ExecutionBackendError(
            "OpenSandbox first-stage execution supports regular-file targets only"
        )
    roots = tuple(root.expanduser().resolve() for root in approved_roots)
    if not any(_is_within(resolved, root) for root in roots):
        raise ExecutionBackendError("OpenSandbox input target is outside approved input roots")
    return resolved


def _read_bounded_file(path: Path, *, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExecutionBackendError("OpenSandbox input cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ExecutionBackendError("OpenSandbox input is not a regular file")
        if metadata.st_size > maximum_bytes:
            raise ExecutionBackendError("OpenSandbox input exceeded the configured limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(maximum_bytes + 1)
        if len(data) > maximum_bytes:
            raise ExecutionBackendError("OpenSandbox input exceeded the configured limit")
        return data
    finally:
        os.close(descriptor)


def _output_mapping(plan: CommandPlan) -> dict[Path, str]:
    captures = {path for path in (plan.stdout_file, plan.stderr_file) if path is not None}
    mapping = {}
    for index, output in enumerate(plan.output_files):
        if output not in captures:
            mapping[output] = f"{_WORK}/output/{index:03d}-{_safe_filename(output.name)}"
    return mapping


def _rewrite_argv(
    plan: CommandPlan,
    *,
    runtime: OpenSandboxRuntimeSpec,
    target: Path,
    sandbox_target: str,
    output_mapping: Mapping[Path, str],
) -> tuple[str, ...]:
    host_target = str(target)
    output_strings = {str(host): sandbox for host, sandbox in output_mapping.items()}
    rewritten = []
    for index, argument in enumerate(plan.argv):
        if index == 0:
            rewritten.append(runtime.executable)
            continue
        value = argument
        if value == host_target:
            value = sandbox_target
        elif value == f"file:{host_target}":
            value = f"file:{sandbox_target}"
        elif value == f"dir:{host_target}":
            raise ExecutionBackendError("OpenSandbox does not stage directory targets yet")
        for host_output, sandbox_output in output_strings.items():
            if host_output in value:
                value = value.replace(host_output, sandbox_output)
        if value.startswith("/") and value != sandbox_target and Path(value).exists():
            raise ExecutionBackendError(
                "OpenSandbox plan contains an additional host input path that is not staged"
            )
        rewritten.append(value)
    return tuple(rewritten)


def _parse_status(raw: bytes) -> dict[str, object]:
    if len(raw) > 64000:
        raise ExecutionBackendError("OpenSandbox status receipt exceeded its fixed limit")
    try:
        status = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutionBackendError("OpenSandbox status receipt is invalid") from exc
    if not isinstance(status, dict):
        raise ExecutionBackendError("OpenSandbox status receipt must be an object")
    return status


def _bounded_sandbox_read(
    sdk: _SandboxSdk,
    sandbox: object,
    path: str,
    maximum_bytes: int,
    label: str,
) -> bytes:
    data = sdk.read_bytes(sandbox, path)
    if len(data) > maximum_bytes:
        raise ExecutionBackendError(
            f"OpenSandbox tool {label} exceeded the configured output limit"
        )
    return data


def _collect_artifacts(
    sdk: _SandboxSdk,
    sandbox: object,
    *,
    status: dict[str, object],
    output_mapping: Mapping[Path, str],
    maximum_bytes: int,
) -> tuple[BackendArtifact, ...]:
    declared = status.get("artifacts", [])
    if not isinstance(declared, list):
        raise ExecutionBackendError("OpenSandbox artifact receipt is invalid")
    reverse = {sandbox_path: host_path for host_path, sandbox_path in output_mapping.items()}
    artifacts = []
    seen = set()
    for item in declared:
        if not isinstance(item, dict):
            raise ExecutionBackendError("OpenSandbox artifact receipt entry is invalid")
        sandbox_path = item.get("path")
        size = item.get("size")
        if not isinstance(sandbox_path, str) or sandbox_path not in reverse:
            raise ExecutionBackendError("OpenSandbox returned an undeclared artifact")
        if sandbox_path in seen:
            raise ExecutionBackendError("OpenSandbox returned a duplicate artifact")
        if not isinstance(size, int) or size < 0 or size > maximum_bytes:
            raise ExecutionBackendError("OpenSandbox returned an invalid artifact size")
        data = sdk.read_bytes(sandbox, sandbox_path)
        if len(data) != size or len(data) > maximum_bytes:
            raise ExecutionBackendError("OpenSandbox artifact changed during transfer")
        artifacts.append(BackendArtifact(host_path=reverse[sandbox_path], data=data))
        seen.add(sandbox_path)
    return tuple(artifacts)


def _status_int(status: dict[str, object], key: str) -> int:
    value = status.get(key)
    if not isinstance(value, int):
        raise ExecutionBackendError(f"OpenSandbox status is missing integer {key}")
    return value


def _safe_filename(value: str) -> str:
    cleaned = _SAFE_NAME.sub("_", value).strip("._") or "artifact"
    return cleaned[:128]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
