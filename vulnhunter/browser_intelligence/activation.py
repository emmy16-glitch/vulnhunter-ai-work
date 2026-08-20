"""Environment-driven, fail-closed activation for the Obscura runtime."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .runtime import ObscuraMcpProcess, ObscuraRuntimeConfig

_RUNTIME_ENV = "VULNHUNTER_BROWSER_RUNTIME"
_BINARY_ENV = "VULNHUNTER_OBSCURA_BINARY"
_VERSION_ENV = "VULNHUNTER_OBSCURA_VERSION"
_ARCHIVE_SHA_ENV = "VULNHUNTER_OBSCURA_ARCHIVE_SHA256"
_STARTUP_ENV = "VULNHUNTER_BROWSER_STARTUP_TIMEOUT"
_ACTION_ENV = "VULNHUNTER_BROWSER_ACTION_TIMEOUT"
_IDLE_ENV = "VULNHUNTER_BROWSER_IDLE_TIMEOUT"
_DEFAULT_BINARY = "/home/ubuntu/.local/share/vulnhunter/browser-tools/obscura-0.2.0/obscura"
_DEFAULT_ARCHIVE_SHA256 = "d601f4f542319c3b9fa8dca9f5ccfc134a2ca001648da528db5f03c9e6c2599b"


class BrowserActivationError(ValueError):
    """Raised when Obscura activation is incomplete or unsafe."""


@dataclass(frozen=True)
class BrowserActivationConfig:
    runtime: str = "playwright"
    binary: Path | None = None
    version: str = "0.2.0"
    archive_sha256: str = _DEFAULT_ARCHIVE_SHA256
    startup_timeout_seconds: float = 8.0
    action_timeout_seconds: float = 30.0
    idle_timeout_seconds: float = 120.0

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> BrowserActivationConfig:
        values = os.environ if environ is None else environ
        runtime = values.get(_RUNTIME_ENV, "playwright").strip().casefold()
        if runtime not in {"playwright", "obscura"}:
            raise BrowserActivationError(f"{_RUNTIME_ENV} must be playwright or obscura")
        binary_value = values.get(_BINARY_ENV, _DEFAULT_BINARY).strip()
        binary = Path(binary_value) if binary_value else None
        return cls(
            runtime=runtime,
            binary=binary,
            version=values.get(_VERSION_ENV, "0.2.0").strip(),
            archive_sha256=values.get(_ARCHIVE_SHA_ENV, _DEFAULT_ARCHIVE_SHA256).strip().lower(),
            startup_timeout_seconds=_float_value(values, _STARTUP_ENV, 8.0, 1.0, 60.0),
            action_timeout_seconds=_float_value(values, _ACTION_ENV, 30.0, 1.0, 120.0),
            idle_timeout_seconds=_float_value(values, _IDLE_ENV, 120.0, 30.0, 900.0),
        )

    def build_obscura(self) -> ObscuraMcpProcess | None:
        if self.runtime != "obscura":
            return None
        if self.binary is None:
            raise BrowserActivationError(f"{_BINARY_ENV} is required for Obscura")
        try:
            config = ObscuraRuntimeConfig(
                binary=self.binary,
                expected_version=self.version,
                archive_sha256=self.archive_sha256,
                startup_timeout_seconds=self.startup_timeout_seconds,
                action_timeout_seconds=self.action_timeout_seconds,
                idle_timeout_seconds=self.idle_timeout_seconds,
            )
        except ValueError as exc:
            raise BrowserActivationError(str(exc)) from exc
        return ObscuraMcpProcess(config)


def _float_value(
    values: Mapping[str, str], name: str, default: float, minimum: float, maximum: float
) -> float:
    raw = values.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise BrowserActivationError(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise BrowserActivationError(f"{name} is outside its bounded range")
    return value


__all__ = ["BrowserActivationConfig", "BrowserActivationError"]
