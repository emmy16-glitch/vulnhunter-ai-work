"""Exact-target OpenSandbox execution for the first governed Nuclei website worker."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from vulnhunter.security_tools.execution_backend import (
    BackendExecutionResult,
    ExecutionBackendError,
    OpenSandboxConnection,
    _CONTROL,
    _PLAN,
    _ROOT,
    _RUNNER,
    _RUNNER_SOURCE,
    _WORK,
    _bounded_sandbox_read,
    _collect_artifacts,
    _output_mapping,
    _parse_status,
    _status_int,
)
from vulnhunter.security_tools.models import (
    CommandPlan,
    NetworkTargetBinding,
    SecurityToolRequest,
    ToolTargetKind,
)

_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NUCLEI_EXECUTABLE = "/usr/local/bin/nuclei"
_NUCLEI_TEMPLATE_ROOT = "/opt/vulnhunter/templates"
Resolver = Callable[[str, int], tuple[str, ...]]


@dataclass(frozen=True)
class NucleiOpenSandboxRuntimeSpec:
    """Pinned scanner and reviewed-template identity for one Nuclei worker image."""

    image: str
    template_manifest_sha256: str
    executable: str = _NUCLEI_EXECUTABLE
    template_root: str = _NUCLEI_TEMPLATE_ROOT
    cpu: str = "1"
    memory: str = "1Gi"
    uid: int = 65532
    gid: int = 65532
    path: str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    def __post_init__(self) -> None:
        if _IMAGE_DIGEST.fullmatch(self.image) is None:
            raise ValueError("OpenSandbox Nuclei worker image must be pinned by sha256 digest")
        if _SHA256.fullmatch(self.template_manifest_sha256) is None:
            raise ValueError("OpenSandbox Nuclei template manifest must be pinned by SHA-256")
        if not self.executable.startswith("/") or not self.template_root.startswith("/"):
            raise ValueError("OpenSandbox Nuclei runtime paths must be absolute")
        if self.uid <= 0 or self.gid <= 0:
            raise ValueError("OpenSandbox Nuclei execution must use a non-root uid and gid")
        if not self.cpu or not self.memory or not self.path:
            raise ValueError("OpenSandbox Nuclei runtime resource fields must not be empty")


class _OpenSandboxNetworkSdkV015:
    """Minimal OpenSandbox 0.1.15 adapter with one exact allowed IPv4 egress rule."""

    def __init__(self, connection: OpenSandboxConnection) -> None:
        self.connection = connection

    def create(
        self,
        *,
        runtime: NucleiOpenSandboxRuntimeSpec,
        allowed_ip: str,
        lifetime_seconds: int,
        metadata: dict[str, str],
    ) -> object:
        try:
            from opensandbox import SandboxSync
            from opensandbox.config import ConnectionConfigSync
            from opensandbox.models.sandboxes import NetworkPolicy, NetworkRule
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
            network_policy=NetworkPolicy(
                defaultAction="deny",
                egress=[NetworkRule(action="allow", target=allowed_ip)],
            ),
            metadata=metadata,
            env={},
        )

    @staticmethod
    def make_directory(sandbox: object, path: str, *, mode: int) -> None:
        try:
            from opensandbox.models.filesystem import WriteEntry
        except ImportError as exc:
            raise ExecutionBackendError("OpenSandbox filesystem models are unavailable") from exc
        sandbox.files.create_directories([WriteEntry(path=path, mode=_permission_mode(mode))])

    @staticmethod
    def write_file(
        sandbox: object,
        path: str,
        data: str | bytes,
        *,
        mode: int,
    ) -> None:
        sandbox.files.write_file(path, data, mode=_permission_mode(mode))

    @staticmethod
    def run_fixed_runner(
        sandbox: object,
        *,
        runtime: NucleiOpenSandboxRuntimeSpec,
        timeout_seconds: int,
    ) -> int:
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
        if execution.exit_code is None:
            detail = "no structured error"
            if execution.error is not None:
                name = str(execution.error.name).strip() or "ExecutionError"
                value = " ".join(str(execution.error.value).split())[:240]
                detail = f"{name}: {value}" if value else name
            raise ExecutionBackendError(
                f"OpenSandbox Nuclei runner returned no exit code ({detail})"
            )
        return execution.exit_code

    @staticmethod
    def read_bytes(sandbox: object, path: str) -> bytes:
        return sandbox.files.read_bytes(path)

    @staticmethod
    def destroy(sandbox: object) -> None:
        sandbox.destroy()


class OpenSandboxNucleiExecutionBackend:
    """Run only passive reviewed Nuclei HTTP templates against one pinned IPv4 target."""

    isolated = True

    def __init__(
        self,
        *,
        runtime: NucleiOpenSandboxRuntimeSpec,
        connection: OpenSandboxConnection | None = None,
        resolver: Resolver | None = None,
        sdk: object | None = None,
    ) -> None:
        self.runtime = runtime
        self.connection = connection or OpenSandboxConnection()
        self._resolver = resolver or _resolve_ipv4
        self._sdk = sdk or _OpenSandboxNetworkSdkV015(self.connection)

    def executable_for(self, tool_id: str) -> str | None:
        return self.runtime.executable if tool_id == "nuclei" else None

    def bind_plan(self, plan: CommandPlan, request: SecurityToolRequest) -> CommandPlan:
        if plan.tool_id != "nuclei" or request.tool_id != "nuclei":
            raise ExecutionBackendError("OpenSandbox Nuclei backend received a non-Nuclei plan")
        if request.target_kind != ToolTargetKind.NETWORK:
            raise ExecutionBackendError("OpenSandbox Nuclei worker accepts network URL targets only")
        if str(request.parameters.get("scan_profile", "passive")).strip().lower() != "passive":
            raise ExecutionBackendError("first OpenSandbox Nuclei worker supports passive scans only")
        if request.parameters.get("template_ids"):
            raise ExecutionBackendError(
                "first OpenSandbox Nuclei worker uses only its baked reviewed template bundle"
            )

        binding = _bind_network_target(
            request.target,
            approved_ip=request.parameters.get("approved_ip"),
            resolver=self._resolver,
        )
        argv = _bind_nuclei_argv(plan.argv, original_target=request.target, binding=binding, runtime=self.runtime)
        return plan.model_copy(
            update={
                "argv": argv,
                "target": request.target,
                "target_kind": ToolTargetKind.NETWORK,
                "runtime_image": self.runtime.image,
                "template_manifest_sha256": self.runtime.template_manifest_sha256,
                "network_binding": binding,
                "requires_isolation": True,
            }
        )

    def execute(
        self,
        plan: CommandPlan,
        *,
        approved_input_roots: tuple[Path, ...] = (),
    ) -> BackendExecutionResult:
        del approved_input_roots
        self._validate_bound_plan(plan)
        binding = plan.network_binding
        if binding is None:
            raise ExecutionBackendError("OpenSandbox Nuclei plan has no network binding")
        _revalidate_binding(binding, resolver=self._resolver)

        output_mapping = _output_mapping(plan)
        argv = _rewrite_output_paths(plan.argv, output_mapping)
        payload = {
            "argv": list(argv),
            "timeout_seconds": plan.timeout_seconds,
            "maximum_output_bytes": plan.maximum_output_bytes,
            "working_directory": _WORK,
            "outputs": list(output_mapping.values()),
            "environment": {
                "PATH": self.runtime.path,
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
                runtime=self.runtime,
                allowed_ip=binding.ip_address,
                lifetime_seconds=min(max(plan.timeout_seconds + 90, 120), 86490),
                metadata={
                    "project": "vulnhunter",
                    "tool": "nuclei",
                    "request": plan.request_id,
                },
            )
            self._prepare(sandbox, payload=payload)
            wrapper_exit = self._sdk.run_fixed_runner(
                sandbox,
                runtime=self.runtime,
                timeout_seconds=min(plan.timeout_seconds + 30, 86430),
            )
            if wrapper_exit != 0:
                raise ExecutionBackendError(
                    "OpenSandbox Nuclei fixed runner failed before producing trusted evidence"
                )
            result = self._collect(sandbox, plan=plan, output_mapping=output_mapping)
        except ExecutionBackendError as exc:
            failure = exc
        except Exception as exc:
            failure = ExecutionBackendError(
                f"OpenSandbox Nuclei execution failed closed: {type(exc).__name__}"
            )
            failure.__cause__ = exc
        finally:
            if sandbox is not None:
                try:
                    self._sdk.destroy(sandbox)
                except Exception as exc:
                    if failure is None:
                        raise ExecutionBackendError(
                            f"OpenSandbox Nuclei destruction failed: {type(exc).__name__}"
                        ) from exc

        if failure is not None:
            raise failure
        if result is None:
            raise ExecutionBackendError("OpenSandbox Nuclei execution produced no result")
        return result

    def _validate_bound_plan(self, plan: CommandPlan) -> None:
        if plan.tool_id != "nuclei" or plan.target_kind != ToolTargetKind.NETWORK:
            raise ExecutionBackendError("OpenSandbox Nuclei backend accepts only Nuclei network plans")
        if plan.runtime_image != self.runtime.image:
            raise ExecutionBackendError("OpenSandbox Nuclei runtime image changed after plan issuance")
        if plan.template_manifest_sha256 != self.runtime.template_manifest_sha256:
            raise ExecutionBackendError(
                "OpenSandbox Nuclei reviewed-template identity changed after plan issuance"
            )
        if plan.network_binding is None:
            raise ExecutionBackendError("OpenSandbox Nuclei plan is missing its bound network target")
        if plan.executable != self.runtime.executable or plan.argv[0] != self.runtime.executable:
            raise ExecutionBackendError("OpenSandbox Nuclei executable identity changed")

    def _prepare(self, sandbox: object, *, payload: dict[str, object]) -> None:
        for path, mode in (
            (_ROOT, 0o755),
            (_CONTROL, 0o733),
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

    def _collect(
        self,
        sandbox: object,
        *,
        plan: CommandPlan,
        output_mapping: Mapping[Path, str],
    ) -> BackendExecutionResult:
        status = _parse_status(self._sdk.read_bytes(sandbox, f"{_CONTROL}/status.json"))
        if status.get("runner_error"):
            raise ExecutionBackendError(
                f"OpenSandbox Nuclei fixed runner failed closed: {status['runner_error']}"
            )
        if status.get("capture_overflow") is True:
            raise ExecutionBackendError(
                "OpenSandbox Nuclei stdout/stderr exceeded the configured output limit"
            )
        if status.get("artifact_error"):
            raise ExecutionBackendError(str(status["artifact_error"]))
        stdout = _bounded_sandbox_read(
            self._sdk,
            sandbox,
            f"{_CONTROL}/stdout.bin",
            plan.maximum_output_bytes,
            "stdout",
        )
        stderr = _bounded_sandbox_read(
            self._sdk,
            sandbox,
            f"{_CONTROL}/stderr.bin",
            plan.maximum_output_bytes,
            "stderr",
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


def _permission_mode(mode: int) -> int:
    if mode < 0 or mode > 0o7777:
        raise ExecutionBackendError("OpenSandbox permission mode is outside the POSIX range")
    return int(format(mode, "o"), 10)


def _resolve_ipv4(hostname: str, port: int) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ExecutionBackendError("OpenSandbox Nuclei target DNS resolution failed") from exc
    addresses = sorted({record[4][0] for record in records if record[4]})
    if not addresses:
        raise ExecutionBackendError("OpenSandbox Nuclei target resolved to no IPv4 address")
    return tuple(addresses)


def _bind_network_target(
    target: str,
    *,
    approved_ip: object,
    resolver: Resolver,
) -> NetworkTargetBinding:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ExecutionBackendError("OpenSandbox Nuclei target must be one http or https URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ExecutionBackendError(
            "OpenSandbox Nuclei target must not contain credentials or URL fragments"
        )
    hostname = parsed.hostname.rstrip(".").casefold()
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None and literal.version != 4:
        raise ExecutionBackendError("first OpenSandbox Nuclei worker supports IPv4 targets only")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = (str(literal),) if literal is not None else resolver(hostname, port)
    addresses = tuple(sorted({_validated_ipv4(value) for value in addresses}))
    if not addresses:
        raise ExecutionBackendError("OpenSandbox Nuclei target has no approved IPv4 destination")

    if approved_ip is not None:
        if not isinstance(approved_ip, str):
            raise ExecutionBackendError("nuclei approved_ip must be an IPv4 string")
        pinned_ip = _validated_ipv4(approved_ip.strip())
        if pinned_ip not in addresses:
            raise ExecutionBackendError(
                "nuclei approved_ip is not present in the target's current DNS result"
            )
    else:
        pinned_ip = addresses[0]

    path = parsed.path or "/"
    connect_url = urlunsplit(
        (parsed.scheme, f"{pinned_ip}:{port}", path, parsed.query, "")
    )
    default_port = 443 if parsed.scheme == "https" else 80
    host_header = hostname if port == default_port else f"{hostname}:{port}"
    tls_server_name = hostname if parsed.scheme == "https" and literal is None else None
    return NetworkTargetBinding(
        scheme=parsed.scheme,
        hostname=hostname,
        ip_address=pinned_ip,
        port=port,
        connect_url=connect_url,
        host_header=host_header,
        tls_server_name=tls_server_name,
    )


def _revalidate_binding(binding: NetworkTargetBinding, *, resolver: Resolver) -> None:
    try:
        literal = ipaddress.ip_address(binding.hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if str(literal) != binding.ip_address:
            raise ExecutionBackendError("literal network target changed after plan issuance")
        return
    addresses = tuple(sorted({_validated_ipv4(value) for value in resolver(binding.hostname, binding.port)}))
    if binding.ip_address not in addresses:
        raise ExecutionBackendError(
            "OpenSandbox Nuclei target DNS changed after authorization; execution denied"
        )


def _validated_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ExecutionBackendError("OpenSandbox Nuclei resolver returned an invalid IP") from exc
    if address.version != 4:
        raise ExecutionBackendError("first OpenSandbox Nuclei worker supports IPv4 only")
    return str(address)


def _bind_nuclei_argv(
    argv: tuple[str, ...],
    *,
    original_target: str,
    binding: NetworkTargetBinding,
    runtime: NucleiOpenSandboxRuntimeSpec,
) -> tuple[str, ...]:
    rewritten: list[str] = []
    index = 0
    while index < len(argv):
        value = argv[index]
        if index == 0:
            rewritten.append(runtime.executable)
            index += 1
            continue
        if value in {"-disable-unsigned-templates", "-restrict-local-network-access"}:
            index += 1
            continue
        if value in {"-type", "-tags"}:
            if index + 1 >= len(argv):
                raise ExecutionBackendError(f"Nuclei command is missing a value for {value}")
            rewritten.extend((value, "http" if value == "-type" else "vulnhunter"))
            index += 2
            continue
        rewritten.append(binding.connect_url if value == original_target else value)
        index += 1

    forbidden = {"-templates", "-template", "-header", "-H", "-sni", "-disable-redirects", "-no-httpx"}
    if any(value in forbidden for value in rewritten):
        raise ExecutionBackendError("Nuclei adapter unexpectedly pre-bound sandbox-only arguments")
    rewritten.extend(("-templates", runtime.template_root, "-disable-redirects", "-no-httpx"))
    if binding.hostname != binding.ip_address:
        rewritten.extend(("-header", f"Host: {binding.host_header}"))
    if binding.tls_server_name is not None:
        rewritten.extend(("-sni", binding.tls_server_name))
    return tuple(rewritten)


def _rewrite_output_paths(
    argv: tuple[str, ...],
    output_mapping: Mapping[Path, str],
) -> tuple[str, ...]:
    output_strings = {str(host): sandbox for host, sandbox in output_mapping.items()}
    rewritten = []
    for value in argv:
        candidate = value
        for host_output, sandbox_output in output_strings.items():
            if host_output in candidate:
                candidate = candidate.replace(host_output, sandbox_output)
        rewritten.append(candidate)
    return tuple(rewritten)
