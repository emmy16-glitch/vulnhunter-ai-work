"""Strict validation for authorised laboratory targets."""

from __future__ import annotations

import ipaddress
import posixpath
import socket
from collections.abc import Callable, Iterable
from urllib.parse import unquote, urlsplit, urlunsplit

from vulnhunter.exceptions import ScopeValidationError
from vulnhunter.scope.models import ApprovedTarget

Resolver = Callable[[str], Iterable[str]]

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_DECODE_PASSES = 3

_ALLOWED_IPV4_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def system_resolver(hostname: str) -> tuple[str, ...]:
    """Resolve a hostname using the operating system DNS configuration."""
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ScopeValidationError(f"Hostname could not be resolved: {hostname}") from exc

    addresses = sorted({result[4][0] for result in results})

    if not addresses:
        raise ScopeValidationError(f"Hostname returned no usable addresses: {hostname}")

    return tuple(addresses)


def _decode_path(path: str) -> str:
    """Decode a URL path repeatedly to expose encoded traversal segments."""
    decoded = path or "/"

    for _ in range(_MAX_DECODE_PASSES):
        updated = unquote(decoded)

        if updated == decoded:
            break

        decoded = updated

    return decoded


def normalize_path(path: str) -> str:
    """Validate and normalize a URL path used as a scope boundary."""
    decoded = _decode_path(path)

    if "\\" in decoded:
        raise ScopeValidationError("Backslashes are not permitted in target paths.")

    if any(ord(character) < 32 for character in decoded):
        raise ScopeValidationError("Control characters are not permitted in target paths.")

    segments = decoded.split("/")

    if any(segment in {".", ".."} for segment in segments):
        raise ScopeValidationError("Dot-segment path traversal is not permitted.")

    normalized = posixpath.normpath("/" + decoded.lstrip("/"))

    if decoded.endswith("/") and normalized != "/" and not normalized.endswith("/"):
        normalized += "/"

    return normalized


def _validate_ip_address(address_text: str) -> str:
    """Return a normalized address when it is explicitly allowed for lab use."""
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError as exc:
        raise ScopeValidationError(
            f"Resolver returned an invalid IP address: {address_text}"
        ) from exc

    if address.is_unspecified:
        raise ScopeValidationError(f"Unspecified addresses are prohibited: {address}")

    if address.is_multicast:
        raise ScopeValidationError(f"Multicast addresses are prohibited: {address}")

    if address.is_link_local:
        raise ScopeValidationError(f"Link-local and metadata addresses are prohibited: {address}")

    # Loopback is explicitly allowed for local laboratory applications.
    # This includes IPv4 127.0.0.0/8 and IPv6 ::1.
    if address.is_loopback:
        return str(address)

    # Do not rely on address.is_private here. Python's definition includes
    # some non-global special-use ranges that are outside VulnHunter's scope.
    if isinstance(address, ipaddress.IPv4Address):
        if any(address in network for network in _ALLOWED_IPV4_NETWORKS):
            return str(address)

    if address.is_reserved:
        raise ScopeValidationError(f"Reserved addresses are prohibited: {address}")

    if address.is_global:
        raise ScopeValidationError(f"Public Internet addresses are prohibited: {address}")

    raise ScopeValidationError(
        f"Address is outside the explicitly allowed laboratory networks: {address}"
    )


def _normalize_hostname(hostname: str) -> str:
    """Convert a hostname to its normalized ASCII/IDNA representation."""
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeValidationError(
            f"Hostname contains invalid Unicode characters: {hostname}"
        ) from exc


def _build_netloc(hostname: str, port: int, default_port: int) -> str:
    """Build a normalized network location, including IPv6 brackets."""
    display_hostname = f"[{hostname}]" if ":" in hostname else hostname

    if port == default_port:
        return display_hostname

    return f"{display_hostname}:{port}"


def validate_target(
    url: str,
    *,
    resolver: Resolver = system_resolver,
) -> ApprovedTarget:
    """Validate and normalize an authorised laboratory target."""
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ScopeValidationError("The target URL is malformed.") from exc

    scheme = parsed.scheme.lower()

    if scheme not in _ALLOWED_SCHEMES:
        raise ScopeValidationError("Only http:// and https:// targets are permitted.")

    if parsed.username is not None or parsed.password is not None:
        raise ScopeValidationError("Credentials must not be embedded inside target URLs.")

    if not parsed.hostname:
        raise ScopeValidationError("The target URL must contain a hostname or IP address.")

    if parsed.query:
        raise ScopeValidationError("Query strings are not permitted when defining a target scope.")

    if parsed.fragment:
        raise ScopeValidationError("URL fragments are not permitted when defining a target scope.")

    hostname = _normalize_hostname(parsed.hostname)

    try:
        port = parsed.port
    except ValueError as exc:
        raise ScopeValidationError("The target URL contains an invalid port.") from exc

    default_port = 443 if scheme == "https" else 80
    effective_port = port or default_port
    normalized_path = normalize_path(parsed.path)

    try:
        direct_address = ipaddress.ip_address(hostname)
    except ValueError:
        resolved_addresses = tuple(resolver(hostname))
    else:
        resolved_addresses = (str(direct_address),)

    if not resolved_addresses:
        raise ScopeValidationError(f"Hostname returned no addresses: {hostname}")

    approved_addresses = tuple(
        sorted({_validate_ip_address(address) for address in resolved_addresses})
    )

    netloc = _build_netloc(
        hostname=hostname,
        port=effective_port,
        default_port=default_port,
    )

    normalized_url = urlunsplit(
        (
            scheme,
            netloc,
            normalized_path,
            "",
            "",
        )
    )

    return ApprovedTarget(
        original_url=url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=effective_port,
        path=normalized_path,
        resolved_addresses=approved_addresses,
    )
