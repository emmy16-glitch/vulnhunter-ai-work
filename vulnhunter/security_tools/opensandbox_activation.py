"""Strict environment activation for digest-pinned OpenSandbox scanner workers."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from vulnhunter.security_tools.execution_backend import (
    OpenSandboxConnection,
    OpenSandboxExecutionBackend,
    OpenSandboxRuntimeSpec,
)

_ENABLED_ENV = "VULNHUNTER_OPENSANDBOX_ENABLED"
_DOMAIN_ENV = "VULNHUNTER_OPENSANDBOX_DOMAIN"
_PROTOCOL_ENV = "VULNHUNTER_OPENSANDBOX_PROTOCOL"
_BANDIT_IMAGE_ENV = "VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE"
_MAX_INPUT_ENV = "VULNHUNTER_OPENSANDBOX_MAX_INPUT_BYTES"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})


class OpenSandboxActivationError(ValueError):
    """Raised when OpenSandbox activation settings are incomplete or unsafe."""


class _PermissionModeSdkAdapter:
    """Translate Python permission integers to OpenSandbox's documented 755 form."""

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

    def __getattr__(self, name: str):
        return getattr(self._delegate, name)


class ConfiguredOpenSandboxExecutionBackend(OpenSandboxExecutionBackend):
    """OpenSandbox backend that can authoritatively resolve its scanner binaries."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # SDK 0.1.15 models permissions as integers such as 755/444 while the
        # backend uses normal Python permission constants such as 0o755/0o444.
        # Keep that wire-format compatibility at the SDK seam.
        self._sdk = _PermissionModeSdkAdapter(self._sdk)

    def executable_for(self, tool_id: str) -> str | None:
        runtime = self.runtimes.get(tool_id)
        return runtime.executable if runtime is not None else None


@dataclass(frozen=True)
class OpenSandboxActivationConfig:
    """Environment-derived activation state for the first production worker."""

    enabled: bool = False
    domain: str = "localhost:8080"
    protocol: Literal["http", "https"] = "http"
    bandit_image: str | None = None
    maximum_input_bytes: int = 50_000_000

    def __post_init__(self) -> None:
        if self.maximum_input_bytes < 1024:
            raise OpenSandboxActivationError(
                "OpenSandbox maximum input size must be at least 1024 bytes"
            )
        _validate_control_plane(self.domain, self.protocol)
        if self.enabled:
            if not self.bandit_image:
                raise OpenSandboxActivationError(
                    f"{_BANDIT_IMAGE_ENV} is required when OpenSandbox is enabled"
                )
            try:
                _bandit_runtime(self.bandit_image)
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
            raise OpenSandboxActivationError(
                f"{_PROTOCOL_ENV} must be either http or https"
            )
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
            maximum_input_bytes=maximum_input_bytes,
        )

    def build_backend(self) -> ConfiguredOpenSandboxExecutionBackend | None:
        if not self.enabled:
            return None
        if self.bandit_image is None:
            raise OpenSandboxActivationError(
                "Enabled OpenSandbox configuration has no worker image"
            )
        return ConfiguredOpenSandboxExecutionBackend(
            runtimes={"bandit": _bandit_runtime(self.bandit_image)},
            connection=OpenSandboxConnection(
                domain=self.domain,
                protocol=self.protocol,
                use_server_proxy=True,
                request_timeout_seconds=30,
                ready_timeout_seconds=45,
            ),
            maximum_input_bytes=self.maximum_input_bytes,
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
