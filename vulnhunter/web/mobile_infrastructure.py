"""Fail-closed readiness projections for infrastructure-backed mobile tools."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings

from vulnhunter.mobile.mobsf import MobSFError, MobSFServiceConfig
from vulnhunter.mobile.runtime import MobileRuntimeError, MobileRuntimePolicy


def _path_from_env(name: str, fallback: str) -> Path:
    return Path(
        os.environ.get(
            name,
            str(Path(settings.BASE_DIR) / ".codespaces" / "runtime" / fallback),
        )
    )


def mobile_infrastructure_status(
    *,
    now: datetime | None = None,
) -> dict[str, dict[str, object]]:
    """Return non-secret readiness metadata without contacting dynamic services."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    return {
        "mobsf": _mobsf_status(),
        "adb": _runtime_status(tool_id="adb", now=current),
        "frida": _runtime_status(tool_id="frida", now=current),
    }


def _mobsf_status() -> dict[str, object]:
    policy_path = _path_from_env("VULNHUNTER_MOBSF_POLICY", "mobsf.json")
    if not policy_path.is_file():
        return {
            "tool_id": "mobsf",
            "state": "gated",
            "reason": "Private MobSF service policy is not configured.",
        }
    try:
        policy = MobSFServiceConfig.from_path(policy_path)
        if not policy.enabled:
            return {
                "tool_id": "mobsf",
                "state": "gated",
                "reason": "Private MobSF service policy is disabled.",
            }
        policy.read_api_key()
    except (OSError, ValueError, MobSFError) as exc:
        return {
            "tool_id": "mobsf",
            "state": "gated",
            "reason": f"MobSF configuration failed closed: {type(exc).__name__}.",
        }
    return {
        "tool_id": "mobsf",
        "state": "approval_required",
        "reason": "Private MobSF is configured; exact scan approval is still required.",
        "service": "loopback",
        "image": policy.image,
    }


def _runtime_status(*, tool_id: str, now: datetime) -> dict[str, object]:
    policy_path = _path_from_env(
        "VULNHUNTER_MOBILE_RUNTIME_POLICY",
        "mobile-runtime.json",
    )
    if not policy_path.is_file():
        return {
            "tool_id": tool_id,
            "state": "gated",
            "reason": "No disposable Android emulator is registered.",
        }
    try:
        policy = MobileRuntimePolicy.from_path(policy_path)
    except (OSError, ValueError, MobileRuntimeError) as exc:
        return {
            "tool_id": tool_id,
            "state": "gated",
            "reason": f"Runtime registration failed closed: {type(exc).__name__}.",
        }
    if not policy.enabled:
        return {
            "tool_id": tool_id,
            "state": "gated",
            "reason": "Disposable Android runtime policy is disabled.",
        }
    if policy.expires_at <= now:
        return {
            "tool_id": tool_id,
            "state": "gated",
            "reason": "Disposable Android runtime registration has expired.",
        }
    return {
        "tool_id": tool_id,
        "state": "approval_required",
        "reason": (
            "Exact APK, package, emulator identity and plan digest approval is required."
        ),
        "runtime_id": policy.runtime_id,
        "expires_at": policy.expires_at.isoformat(),
        "emulator_required": policy.emulator_required,
        "expected_frida_version": (
            policy.expected_frida_version if tool_id == "frida" else None
        ),
    }


__all__ = ["mobile_infrastructure_status"]
