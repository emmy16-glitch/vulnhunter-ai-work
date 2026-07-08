"""Central redaction utilities for logs, storage, URLs, and exports."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from vulnhunter.security.sensitive_patterns import (
    AUTHORIZATION_VALUE_PATTERN,
    EMAIL_PATTERN,
    JWT_PATTERN,
    PAYMENT_CARD_PATTERN,
    REDACTED,
    REDACTED_EMAIL,
    REDACTED_PAYMENT_DATA,
    SECRET_ASSIGNMENT_PATTERN,
    SENSITIVE_KEY_NAMES,
)


def normalize_key(key: str) -> str:
    """Normalise a mapping key before checking whether it is sensitive."""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_sensitive_key(key: str) -> bool:
    """Return whether a key name normally contains secret information."""
    normalized = normalize_key(key)

    if normalized in SENSITIVE_KEY_NAMES:
        return True

    sensitive_suffixes = (
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "sessionid",
        "privatekey",
    )

    return normalized.endswith(sensitive_suffixes)


def redact_text(value: str) -> str:
    """Remove recognisable secrets and personal data from arbitrary text."""
    redacted = AUTHORIZATION_VALUE_PATTERN.sub(
        lambda match: f"{match.group(1)} {REDACTED}",
        value,
    )
    redacted = JWT_PATTERN.sub(REDACTED, redacted)
    redacted = SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}",
        redacted,
    )
    redacted = EMAIL_PATTERN.sub(REDACTED_EMAIL, redacted)
    redacted = PAYMENT_CARD_PATTERN.sub(REDACTED_PAYMENT_DATA, redacted)

    return redacted


def _redact_value(value: Any) -> Any:
    """Recursively redact supported values without mutating the source."""
    if isinstance(value, Mapping):
        return redact_mapping(value)

    if isinstance(value, list):
        return [_redact_value(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)

    if isinstance(value, set):
        return {_redact_value(item) for item in value}

    if isinstance(value, str):
        return redact_text(value)

    return value


def redact_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    """Return a sanitised copy of a mapping.

    A sensitive key causes the entire associated value to be replaced.
    Non-sensitive values are still inspected recursively for embedded secrets.
    """
    redacted: dict[str, Any] = {}

    for key, value in values.items():
        key_text = str(key)

        if is_sensitive_key(key_text):
            redacted[key_text] = REDACTED
        else:
            redacted[key_text] = _redact_value(value)

    return redacted


def redact_url(url: str) -> str:
    """Redact credentials and sensitive query values from a URL."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        # A malformed URL must still be safe to display in an error message.
        return redact_text(url)

    hostname = parsed.hostname or ""
    display_hostname = f"[{hostname}]" if ":" in hostname else hostname
    port_text = f":{port}" if port is not None else ""

    user_info = ""
    if parsed.username is not None or parsed.password is not None:
        user_info = f"{REDACTED}@"

    safe_query_items: list[tuple[str, str]] = []

    for key, value in parse_qsl(
        parsed.query,
        keep_blank_values=True,
        strict_parsing=False,
    ):
        safe_value = REDACTED if is_sensitive_key(key) else redact_text(value)
        safe_query_items.append((key, safe_value))

    safe_fragment = redact_text(parsed.fragment)

    return urlunsplit(
        (
            parsed.scheme,
            f"{user_info}{display_hostname}{port_text}",
            parsed.path,
            urlencode(safe_query_items),
            safe_fragment,
        )
    )


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return HTTP headers that are safe for logs and persistence."""
    result = redact_mapping(headers)
    return {key: str(value) for key, value in result.items()}
