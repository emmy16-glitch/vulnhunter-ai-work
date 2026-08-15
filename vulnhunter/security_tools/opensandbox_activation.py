"""Strict environment activation for signed digest-pinned OpenSandbox scanner workers."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from vulnhunter.security_tools.execution_backend import (
    BackendExecutionResult,
    ExecutionBackendError,
    OpenSandboxConnection,
    OpenSandboxExecutionBackend,
    OpenSandboxRuntimeSpec,
)
from vulnhunter.security_tools.models import CommandPlan, SecurityToolRequest
from vulnhunter.security_tools.opensandbox_network_backend import (
    NucleiOpenSandboxRuntimeSpec,
    OpenSandboxNucleiExecutionBackend,
)
from vulnhunter.security_tools.opensandbox_supply_chain import (
    ApprovedWorkerRelease,
    WorkerReleaseVerificationError,
    load_verified_worker_release_registry,
)

_ENABLED_ENV = "VULNHUNTER_OPENSANDBOX_ENABLED"
_DOMAIN_ENV = "VULNHUNTER_OPENSANDBOX_DOMAIN"
_PROTOCOL_ENV = "VULNHUNTER_OPENSANDBOX_PROTOCOL"
_BANDIT_IMAGE_ENV = "VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE"
_NUCLEI_IMAGE_ENV = "VULNHUNTER_OPENSANDBOX_NUCLEI_IMAGE"
_MAX_INPUT_ENV = "VULNHUNTER_OPENSANDBOX_MAX_INPUT_BYTES"
_RELEASE_REGISTRY_ENV = "VULNHUNTER_OPENSANDBOX_RELEASE_REGISTRY_FILE"
_RELEASE_SIGNATURE_ENV = "VULNHUNTER_OPENSANDBOX_RELEASE_SIGNATURE_FILE"
_RELEASE_PUBLIC_KEY_ENV = "VULNHUNTER_OPENSANDBOX_RELEASE_PUBLIC_KEY_FILE"
_NUCLEI_TEMPLATE_MANIFEST_SHA256 = (
    "088f533aaa631f178bde29c3589d286b3bb136f839772a39d9276f16b545d35c"
)

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})
_FIXED_RUNNER = "/tmp/vulnhunter/control/runner.py"


class OpenSandboxActivationError(ValueError):
    """Raised when OpenSandbox activation settings are incomplete or unsafe."""


class _PermissionModeSdkAdapter:
    """Normalize SDK wire details and reject ambiguous command completion."""

    def __init__(self, delegate: object) -> None:
        self._delegate = delegate

    def make_directory(self, sandbox: object, path: str, *, mode: int) -> None:
        self._delegate.make_directory(
            sandbox,
            path,
            mode=_opensandbox_permission_mode(mode),
        )

    def write_file(
        self,
        sandbox: object,
        path: str,
        data: str | bytes,
        *,
        mode: int,
    ) -> None:
        self._delegate.write_file(
            sandbox,
            path,
            data,
            mode=_opensandbox_permission_mode(mode),
        )

    def run_fixed_runner(
        self,
        sandbox: object,
        *,
        runtime: OpenSandboxRuntimeSpec,
        timeout_seconds: int,
    ) -> int:
        try:
            from opensandbox.models.execd import RunCommandOpts
        except ImportError as exc:
            raise ExecutionBackendError("OpenSandbox command models are unavailable") from exc

        execution = sandbox.commands.run(
            f"python3 {_FIXED_RUNNER}",
            opts=RunCommandOpts(
                working_directory="/tmp/vulnhunter",
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
                f"OpenSandbox fixed runner returned no exit code ({detail})"
            )
        return execution.exit_code

    def __getattr__(self, name: str):
        return getattr(self._delegate, name)


class ConfiguredOpenSandboxExecutionBackend(OpenSandboxExecutionBackend):
    """Configured router for signed offline and exact-target network workers."""

    def __init__(
        self,
        *,
        runtimes: Mapping[str, OpenSandboxRuntimeSpec],
        connection: OpenSandboxConnection,
        maximum_input_bytes: int,
        approved_releases: Mapping[str, ApprovedWorkerRelease],
        release_registry_sha256: str,
        release_key_id: str,
        nuclei_runtime: NucleiOpenSandboxRuntimeSpec | None = None,
    ) -> None:
        super().__init__(
            runtimes=runtimes,
            connection=connection,
            maximum_input_bytes=maximum_input_bytes,
        )
        self._sdk = _PermissionModeSdkAdapter(self._sdk)
        self.approved_releases = dict(approved_releases)
        self.release_registry_sha256 = release_registry_sha256
        self.release_key_id = release_key_id
        self.nuclei_runtime = nuclei_runtime
        self._nuclei_backend = (
            OpenSandboxNucleiExecutionBackend(runtime=nuclei_runtime, connection=connection)
            if nuclei_runtime is not None
            else None
        )

    def executable_for(self, tool_id: str) -> str | None:
        if tool_id == "nuclei":
            return self.nuclei_runtime.executable if self.nuclei_runtime is not None else None
        runtime = self.runtimes.get(tool_id)
        return runtime.executable if runtime is not None else None

    def bind_plan(self, plan: CommandPlan, request: SecurityToolRequest) -> CommandPlan:
        release = self._release_for(plan.tool_id)
        if plan.tool_id == "nuclei":
            if self._nuclei_backend is None:
                raise ExecutionBackendError("OpenSandbox does not provide a Nuclei network runtime")
            bound = self._nuclei_backend.bind_plan(plan, request)
            return self._bind_release_identity(bound, release)
        runtime = self.runtimes.get(plan.tool_id)
        if runtime is None:
            raise ExecutionBackendError(
                f"No digest-pinned OpenSandbox runtime is registered for {plan.tool_id}"
            )
        bound = plan.model_copy(update={"runtime_image": runtime.image})
        return self._bind_release_identity(bound, release)

    def execute(
        self,
        plan: CommandPlan,
        *,
        approved_input_roots: tuple[Path, ...],
    ) -> BackendExecutionResult:
        release = self._release_for(plan.tool_id)
        self._assert_release_identity(plan, release)
        if plan.tool_id == "nuclei":
            if self._nuclei_backend is None:
                raise ExecutionBackendError("OpenSandbox Nuclei runtime is not configured")
            return self._nuclei_backend.execute(
                plan,
                approved_input_roots=approved_input_roots,
            )
        runtime = self.runtimes.get(plan.tool_id)
        if runtime is None or plan.runtime_image != runtime.image:
            raise ExecutionBackendError(
                "OpenSandbox offline worker image identity changed after plan issuance"
            )
        return super().execute(plan, approved_input_roots=approved_input_roots)

    def _release_for(self, tool_id: str) -> ApprovedWorkerRelease:
        release = self.approved_releases.get(tool_id)
        if release is None:
            raise ExecutionBackendError(
                f"OpenSandbox worker {tool_id} has no verified approved release"
            )
        return release

    def _bind_release_identity(
        self,
        plan: CommandPlan,
        release: ApprovedWorkerRelease,
    ) -> CommandPlan:
        if plan.runtime_image != release.image:
            raise ExecutionBackendError(
                "OpenSandbox runtime image does not match its signed approved release"
            )
        return plan.model_copy(
            update={
                "runtime_release_id": release.release_id,
                "runtime_sbom_sha256": release.sbom_sha256,
                "runtime_provenance_sha256": release.provenance_sha256,
                "runtime_source_commit": release.source_commit,
                "runtime_release_registry_sha256": self.release_registry_sha256,
                "runtime_release_key_id": self.release_key_id,
                "runtime_github_provenance_attestation_sha256": (
                    release.github_provenance_attestation_sha256
                ),
                "runtime_github_sbom_attestation_sha256": (release.github_sbom_attestation_sha256),
                "runtime_github_attestation_signer": release.github_attestation_signer,
            }
        )

    def _assert_release_identity(
        self,
        plan: CommandPlan,
        release: ApprovedWorkerRelease,
    ) -> None:
        expected = (
            release.image,
            release.release_id,
            release.sbom_sha256,
            release.provenance_sha256,
            release.source_commit,
            self.release_registry_sha256,
            self.release_key_id,
            release.github_provenance_attestation_sha256,
            release.github_sbom_attestation_sha256,
            release.github_attestation_signer,
        )
        actual = (
            plan.runtime_image,
            plan.runtime_release_id,
            plan.runtime_sbom_sha256,
            plan.runtime_provenance_sha256,
            plan.runtime_source_commit,
            plan.runtime_release_registry_sha256,
            plan.runtime_release_key_id,
            plan.runtime_github_provenance_attestation_sha256,
            plan.runtime_github_sbom_attestation_sha256,
            plan.runtime_github_attestation_signer,
        )
        if actual != expected:
            raise ExecutionBackendError(
                "OpenSandbox worker supply-chain identity changed after plan issuance"
            )


@dataclass(frozen=True)
class OpenSandboxActivationConfig:
    """Environment-derived activation state for signed reviewed OpenSandbox workers."""

    enabled: bool = False
    domain: str = "localhost:8080"
    protocol: Literal["http", "https"] = "http"
    bandit_image: str | None = None
    nuclei_image: str | None = None
    maximum_input_bytes: int = 50_000_000
    release_registry_file: Path | None = None
    release_signature_file: Path | None = None
    release_public_key_file: Path | None = None

    def __post_init__(self) -> None:
        if self.maximum_input_bytes < 1024:
            raise OpenSandboxActivationError(
                "OpenSandbox maximum input size must be at least 1024 bytes"
            )
        _validate_control_plane(self.domain, self.protocol)
        if self.enabled and not (self.bandit_image or self.nuclei_image):
            raise OpenSandboxActivationError(
                f"at least one of {_BANDIT_IMAGE_ENV} or {_NUCLEI_IMAGE_ENV} is required "
                "when OpenSandbox is enabled"
            )
        if self.enabled:
            missing = [
                name
                for name, value in (
                    (_RELEASE_REGISTRY_ENV, self.release_registry_file),
                    (_RELEASE_SIGNATURE_ENV, self.release_signature_file),
                    (_RELEASE_PUBLIC_KEY_ENV, self.release_public_key_file),
                )
                if value is None
            ]
            if missing:
                raise OpenSandboxActivationError(
                    "signed OpenSandbox worker releases are required; missing " + ", ".join(missing)
                )
        try:
            if self.bandit_image:
                _bandit_runtime(self.bandit_image)
            if self.nuclei_image:
                _nuclei_runtime(self.nuclei_image)
        except ValueError as exc:
            raise OpenSandboxActivationError(str(exc)) from exc

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> OpenSandboxActivationConfig:
        values = os.environ if environ is None else environ
        enabled = _parse_bool(values.get(_ENABLED_ENV), name=_ENABLED_ENV, default=False)
        protocol = values.get(_PROTOCOL_ENV, "http").strip().lower()
        if protocol not in {"http", "https"}:
            raise OpenSandboxActivationError(f"{_PROTOCOL_ENV} must be either http or https")
        maximum_input_bytes = _parse_positive_int(
            values.get(_MAX_INPUT_ENV),
            name=_MAX_INPUT_ENV,
            default=50_000_000,
        )
        return cls(
            enabled=enabled,
            domain=values.get(_DOMAIN_ENV, "localhost:8080").strip(),
            protocol=protocol,
            bandit_image=_optional_text(values.get(_BANDIT_IMAGE_ENV)),
            nuclei_image=_optional_text(values.get(_NUCLEI_IMAGE_ENV)),
            maximum_input_bytes=maximum_input_bytes,
            release_registry_file=_optional_path(values.get(_RELEASE_REGISTRY_ENV)),
            release_signature_file=_optional_path(values.get(_RELEASE_SIGNATURE_ENV)),
            release_public_key_file=_optional_path(values.get(_RELEASE_PUBLIC_KEY_ENV)),
        )

    def build_backend(self) -> ConfiguredOpenSandboxExecutionBackend | None:
        if not self.enabled:
            return None
        if (
            self.release_registry_file is None
            or self.release_signature_file is None
            or self.release_public_key_file is None
        ):
            raise OpenSandboxActivationError("signed OpenSandbox release files are required")
        try:
            registry = load_verified_worker_release_registry(
                self.release_registry_file,
                self.release_signature_file,
                self.release_public_key_file,
            )
            approved_releases: dict[str, ApprovedWorkerRelease] = {}
            if self.bandit_image is not None:
                approved_releases["bandit"] = registry.approved_release(
                    "bandit",
                    self.bandit_image,
                )
            if self.nuclei_image is not None:
                approved_releases["nuclei"] = registry.approved_release(
                    "nuclei",
                    self.nuclei_image,
                )
            if not _is_loopback_control_plane(self.domain, self.protocol):
                missing_attestations = [
                    worker_id
                    for worker_id, release in approved_releases.items()
                    if not release.has_github_attestations
                ]
                if missing_attestations:
                    raise WorkerReleaseVerificationError(
                        "remote OpenSandbox activation requires GitHub provenance and SBOM "
                        "attestations for: " + ", ".join(sorted(missing_attestations))
                    )
        except WorkerReleaseVerificationError as exc:
            raise OpenSandboxActivationError(str(exc)) from exc

        connection = OpenSandboxConnection(
            domain=self.domain,
            protocol=self.protocol,
            use_server_proxy=True,
            request_timeout_seconds=30,
            ready_timeout_seconds=45,
        )
        runtimes = {}
        if self.bandit_image is not None:
            runtimes["bandit"] = _bandit_runtime(self.bandit_image)
        nuclei_runtime = (
            _nuclei_runtime(self.nuclei_image) if self.nuclei_image is not None else None
        )
        return ConfiguredOpenSandboxExecutionBackend(
            runtimes=runtimes,
            connection=connection,
            maximum_input_bytes=self.maximum_input_bytes,
            approved_releases=approved_releases,
            release_registry_sha256=registry.registry_sha256,
            release_key_id=registry.key_id,
            nuclei_runtime=nuclei_runtime,
        )


def build_opensandbox_backend_from_environment(
    environ: Mapping[str, str] | None = None,
) -> ConfiguredOpenSandboxExecutionBackend | None:
    """Return a fail-closed managed backend, or None when activation is disabled."""

    return OpenSandboxActivationConfig.from_environment(environ).build_backend()


def _bandit_runtime(image: str) -> OpenSandboxRuntimeSpec:
    return OpenSandboxRuntimeSpec(
        image=image,
        executable="/usr/local/bin/bandit",
        cpu="1",
        memory="512Mi",
        uid=65532,
        gid=65532,
    )


def _nuclei_runtime(image: str) -> NucleiOpenSandboxRuntimeSpec:
    return NucleiOpenSandboxRuntimeSpec(
        image=image,
        template_manifest_sha256=_NUCLEI_TEMPLATE_MANIFEST_SHA256,
        cpu="1",
        memory="1Gi",
        uid=65532,
        gid=65532,
    )


def _opensandbox_permission_mode(mode: int) -> int:
    if mode < 0 or mode > 0o7777:
        raise OpenSandboxActivationError("OpenSandbox permission mode is outside the POSIX range")
    return int(format(mode, "o"), 10)


def _validate_control_plane(domain: str, protocol: str) -> None:
    if not domain or any(character.isspace() for character in domain):
        raise OpenSandboxActivationError("OpenSandbox domain must be a non-empty host[:port]")
    parsed = urlsplit(f"{protocol}://{domain}")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
    ):
        raise OpenSandboxActivationError(
            "OpenSandbox domain must contain only a host and optional port"
        )
    if protocol == "http" and not _is_loopback_host(parsed.hostname):
        raise OpenSandboxActivationError(
            "Remote OpenSandbox control planes must use https; http is loopback-only"
        )


def _is_loopback_control_plane(domain: str, protocol: str) -> bool:
    parsed = urlsplit(f"{protocol}://{domain}")
    return parsed.hostname is not None and _is_loopback_host(parsed.hostname)


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").casefold()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _parse_bool(value: str | None, *, name: str, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().casefold()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise OpenSandboxActivationError(f"{name} must be an explicit boolean value")


def _parse_positive_int(value: str | None, *, name: str, default: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise OpenSandboxActivationError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise OpenSandboxActivationError(f"{name} must be positive")
    return parsed


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _optional_path(value: str | None) -> Path | None:
    text = _optional_text(value)
    return Path(text) if text is not None else None
