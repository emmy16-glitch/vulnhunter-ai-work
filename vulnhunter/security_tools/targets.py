"""Strict parsing for network, local artifact, and Android device targets."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from vulnhunter.security_tools.models import ToolTargetKind

_HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)
_ANDROID_SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CONTAINER_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,511}$")
_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._:-]{1,255}$")


class TargetValidationError(ValueError):
    pass


def _reject_controls(value: str) -> str:
    target = value.strip()
    if not target or any(char in target for char in ("\x00", "\n", "\r")):
        raise TargetValidationError("target contains forbidden or blank content")
    return target


def validate_target_reference(value: str) -> str:
    """Validate one network target token without resolving or contacting it."""

    target = _reject_controls(value)
    if any(char.isspace() for char in target):
        raise TargetValidationError("target must be one non-blank token")
    if len(target) > 2048:
        raise TargetValidationError("target is too long")

    if "://" in target:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"}:
            raise TargetValidationError("only http and https URLs are accepted")
        if parsed.username or parsed.password:
            raise TargetValidationError("embedded URL credentials are forbidden")
        if not parsed.hostname:
            raise TargetValidationError("URL target must include a hostname")
        return target

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    if target.startswith("*."):
        candidate = target[2:]
        if _HOSTNAME.fullmatch(candidate):
            return target.lower()
    if _HOSTNAME.fullmatch(target):
        return target.lower().rstrip(".")

    raise TargetValidationError("target must be an IP, CIDR, hostname, wildcard domain, or URL")


def validate_local_path_reference(
    value: str, *, require_apk: bool = False, require_file: bool = False
) -> str:
    raw = _reject_controls(value)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise TargetValidationError("local targets must use an absolute path")
    if path.is_symlink():
        raise TargetValidationError("symbolic-link targets are not accepted")
    resolved = path.resolve(strict=True)
    if require_apk:
        if not resolved.is_file() or resolved.suffix.lower() != ".apk":
            raise TargetValidationError("APK target must be an existing .apk file")
    elif require_file and not resolved.is_file():
        raise TargetValidationError("binary target must be an existing regular file")
    elif not resolved.exists():
        raise TargetValidationError("local target does not exist")
    return str(resolved)


def validate_android_device_reference(value: str) -> str:
    serial = _reject_controls(value)
    if _ANDROID_SERIAL.fullmatch(serial) is None:
        raise TargetValidationError("Android device reference contains unsupported characters")
    return serial


def validate_container_image_reference(value: str) -> str:
    image = _reject_controls(value)
    if _CONTAINER_IMAGE.fullmatch(image) is None:
        raise TargetValidationError("container image reference is malformed")
    return image


def validate_finding_reference(value: str) -> str:
    reference = _reject_controls(value).lower()
    if _REFERENCE.fullmatch(reference) is None:
        raise TargetValidationError("finding reference is malformed")
    return reference


def validate_tool_target(value: str, kind: ToolTargetKind) -> str:
    if kind == ToolTargetKind.NETWORK:
        return validate_target_reference(value)
    if kind == ToolTargetKind.LOCAL_PATH:
        return validate_local_path_reference(value)
    if kind == ToolTargetKind.BINARY_FILE:
        return validate_local_path_reference(value, require_file=True)
    if kind == ToolTargetKind.APK_FILE:
        return validate_local_path_reference(value, require_apk=True)
    if kind == ToolTargetKind.ANDROID_DEVICE:
        return validate_android_device_reference(value)
    if kind == ToolTargetKind.CONTAINER_IMAGE:
        return validate_container_image_reference(value)
    if kind == ToolTargetKind.FINDING_REFERENCE:
        return validate_finding_reference(value)
    raise TargetValidationError(f"unsupported target kind: {kind}")
