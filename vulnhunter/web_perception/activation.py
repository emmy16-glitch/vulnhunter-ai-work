"""Strict environment activation for the signed passive Playwright worker."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from vulnhunter.security_tools.execution_backend import OpenSandboxConnection
from vulnhunter.security_tools.opensandbox_supply_chain import (
    WorkerReleaseVerificationError,
    load_verified_worker_release_registry,
)
from vulnhunter.web_perception.backend import (
    OpenSandboxWebPerceptionBackend,
    PlaywrightOpenSandboxRuntimeSpec,
)
from vulnhunter.web_perception.errors import WebPerceptionError

_ENABLED_ENV = "VULNHUNTER_WEB_PERCEPTION_ENABLED"
_IMAGE_ENV = "VULNHUNTER_WEB_PERCEPTION_PLAYWRIGHT_IMAGE"
_DOMAIN_ENV = "VULNHUNTER_OPENSANDBOX_DOMAIN"
_PROTOCOL_ENV = "VULNHUNTER_OPENSANDBOX_PROTOCOL"
_REGISTRY_ENV = "VULNHUNTER_OPENSANDBOX_RELEASE_REGISTRY_FILE"
_SIGNATURE_ENV = "VULNHUNTER_OPENSANDBOX_RELEASE_SIGNATURE_FILE"
_PUBLIC_KEY_ENV = "VULNHUNTER_OPENSANDBOX_RELEASE_PUBLIC_KEY_FILE"
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})


class WebPerceptionActivationError(WebPerceptionError):
    """Raised when browser-perception activation configuration is unsafe."""


@dataclass(frozen=True)
class WebPerceptionActivationConfig:
    """Environment-derived configuration for one signed Playwright worker."""

    enabled: bool = False
    image: str | None = None
    domain: str = "localhost:8080"
    protocol: Literal["http", "https"] = "http"
    release_registry_file: Path | None = None
    release_signature_file: Path | None = None
    release_public_key_file: Path | None = None

    def __post_init__(self) -> None:
        _validate_control_plane(self.domain, self.protocol)
        if self.enabled and self.image is None:
            raise WebPerceptionActivationError(
                f"{_IMAGE_ENV} is required when browser perception is enabled"
            )
        if self.enabled:
            missing = [
                name
                for name, value in (
                    (_REGISTRY_ENV, self.release_registry_file),
                    (_SIGNATURE_ENV, self.release_signature_file),
                    (_PUBLIC_KEY_ENV, self.release_public_key_file),
                )
                if value is None
            ]
            if missing:
                raise WebPerceptionActivationError(
                    "signed Playwright worker release files are required; missing "
                    + ", ".join(missing)
                )
        if self.image is not None:
            try:
                PlaywrightOpenSandboxRuntimeSpec(image=self.image)
            except ValueError as exc:
                raise WebPerceptionActivationError(str(exc)) from exc

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> WebPerceptionActivationConfig:
        values = os.environ if environ is None else environ
        enabled = _parse_bool(values.get(_ENABLED_ENV))
        protocol = values.get(_PROTOCOL_ENV, "http").strip().lower()
        if protocol not in {"http", "https"}:
            raise WebPerceptionActivationError(f"{_PROTOCOL_ENV} must be either http or https")
        return cls(
            enabled=enabled,
            image=_optional_text(values.get(_IMAGE_ENV)),
            domain=values.get(_DOMAIN_ENV, "localhost:8080").strip(),
            protocol=protocol,
            release_registry_file=_optional_path(values.get(_REGISTRY_ENV)),
            release_signature_file=_optional_path(values.get(_SIGNATURE_ENV)),
            release_public_key_file=_optional_path(values.get(_PUBLIC_KEY_ENV)),
        )

    def build_backend(self) -> OpenSandboxWebPerceptionBackend | None:
        if not self.enabled:
            return None
        if (
            self.image is None
            or self.release_registry_file is None
            or self.release_signature_file is None
            or self.release_public_key_file is None
        ):
            raise WebPerceptionActivationError("browser perception activation is incomplete")
        try:
            registry = load_verified_worker_release_registry(
                self.release_registry_file,
                self.release_signature_file,
                self.release_public_key_file,
            )
            release = registry.approved_release("playwright", self.image)
        except WorkerReleaseVerificationError as exc:
            raise WebPerceptionActivationError(str(exc)) from exc

        if not _is_loopback_control_plane(self.domain, self.protocol):
            if not release.has_github_attestations:
                raise WebPerceptionActivationError(
                    "remote browser perception requires GitHub provenance and SBOM attestations"
                )

        connection = OpenSandboxConnection(
            domain=self.domain,
            protocol=self.protocol,
            use_server_proxy=True,
            request_timeout_seconds=30,
            ready_timeout_seconds=45,
        )
        return OpenSandboxWebPerceptionBackend(
            runtime=PlaywrightOpenSandboxRuntimeSpec(image=self.image),
            release=release,
            release_registry_sha256=registry.registry_sha256,
            release_key_id=registry.key_id,
            connection=connection,
        )


def build_web_perception_backend_from_environment(
    environ: Mapping[str, str] | None = None,
) -> OpenSandboxWebPerceptionBackend | None:
    return WebPerceptionActivationConfig.from_environment(environ).build_backend()


def _validate_control_plane(domain: str, protocol: str) -> None:
    if not domain or any(character.isspace() for character in domain):
        raise WebPerceptionActivationError("OpenSandbox domain must be a non-empty host[:port]")
    parsed = urlsplit(f"{protocol}://{domain}")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
    ):
        raise WebPerceptionActivationError(
            "OpenSandbox domain must contain only a host and optional port"
        )
    if protocol == "http" and not _is_loopback_host(parsed.hostname):
        raise WebPerceptionActivationError("remote OpenSandbox control planes must use https")


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


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().casefold()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise WebPerceptionActivationError(f"{_ENABLED_ENV} must be an explicit boolean value")


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _optional_path(value: str | None) -> Path | None:
    value = _optional_text(value)
    return Path(value) if value is not None else None
