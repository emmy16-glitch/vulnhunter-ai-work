"""Validation for links, redirects, and other URLs derived from an approved target."""

from __future__ import annotations

import ipaddress
from urllib.parse import urljoin, urlsplit, urlunsplit

from vulnhunter.exceptions import ScopeValidationError, ScopeViolationError
from vulnhunter.scope.models import ApprovedTarget, ScopedUrl
from vulnhunter.scope.validator import (
    Resolver,
    normalize_hostname,
    normalize_path,
    system_resolver,
)

_ALLOWED_SCHEMES = {"http", "https"}


def _default_port(scheme: str) -> int:
    """Return the standard port for a supported HTTP scheme."""
    if scheme == "https":
        return 443

    return 80


def _build_netloc(hostname: str, port: int, default_port: int) -> str:
    """Build a normalised network location with correct IPv6 brackets."""
    display_hostname = f"[{hostname}]" if ":" in hostname else hostname

    if port == default_port:
        return display_hostname

    return f"{display_hostname}:{port}"


def _path_is_within_boundary(candidate_path: str, boundary_path: str) -> bool:
    """Return whether a path is inside the approved path boundary.

    Segment-aware comparison prevents `/app` from accidentally approving
    `/application`.
    """
    boundary = boundary_path.rstrip("/") or "/"

    if boundary == "/":
        return True

    return candidate_path == boundary or candidate_path.startswith(f"{boundary}/")


def _resolve_current_addresses(
    hostname: str,
    resolver: Resolver,
) -> tuple[str, ...]:
    """Resolve and normalise the addresses currently associated with a host."""
    try:
        direct_address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            raw_addresses = tuple(resolver(hostname))
        except ScopeValidationError as exc:
            raise ScopeViolationError(str(exc)) from exc
    else:
        raw_addresses = (str(direct_address),)

    if not raw_addresses:
        raise ScopeViolationError("The derived URL hostname returned no usable addresses.")

    normalised_addresses: set[str] = set()

    for address_text in raw_addresses:
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise ScopeViolationError(
                "The resolver returned an invalid address for a derived URL."
            ) from exc

        normalised_addresses.add(str(address))

    return tuple(sorted(normalised_addresses))


def _validate_absolute_url(
    target: ApprovedTarget,
    absolute_url: str,
    *,
    resolver: Resolver,
) -> ScopedUrl:
    """Validate one absolute URL against an immutable approved target."""
    try:
        parsed = urlsplit(absolute_url)
    except ValueError as exc:
        raise ScopeViolationError("The derived URL is malformed.") from exc

    scheme = parsed.scheme.lower()

    if scheme not in _ALLOWED_SCHEMES:
        raise ScopeViolationError("Only HTTP and HTTPS derived URLs are permitted.")

    if scheme != target.scheme:
        raise ScopeViolationError("The derived URL attempted to change the approved scheme.")

    if parsed.username is not None or parsed.password is not None:
        raise ScopeViolationError("Credentials are not permitted inside derived URLs.")

    if not parsed.hostname:
        raise ScopeViolationError("The derived URL does not contain a valid hostname.")

    try:
        hostname = normalize_hostname(parsed.hostname)
    except ScopeValidationError as exc:
        raise ScopeViolationError(str(exc)) from exc

    if hostname != target.hostname:
        raise ScopeViolationError("The derived URL attempted to leave the approved hostname.")

    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ScopeViolationError("The derived URL contains an invalid port.") from exc

    default_port = _default_port(scheme)
    port = parsed_port or default_port

    if port != target.port:
        raise ScopeViolationError("The derived URL attempted to change the approved port.")

    try:
        path = normalize_path(parsed.path)
    except ScopeValidationError as exc:
        raise ScopeViolationError(str(exc)) from exc

    if not _path_is_within_boundary(path, target.path):
        raise ScopeViolationError("The derived URL attempted to leave the approved path boundary.")

    current_addresses = _resolve_current_addresses(hostname, resolver)
    approved_addresses = set(target.resolved_addresses)
    unexpected_addresses = set(current_addresses) - approved_addresses

    if unexpected_addresses:
        raise ScopeViolationError("DNS resolution changed to an address outside the approved set.")

    netloc = _build_netloc(
        hostname=hostname,
        port=port,
        default_port=default_port,
    )

    normalised_url = urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )

    return ScopedUrl(
        url=normalised_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=parsed.query,
        resolved_addresses=current_addresses,
    )


def validate_scoped_url(
    target: ApprovedTarget,
    candidate: str,
    *,
    base_url: str | None = None,
    resolver: Resolver = system_resolver,
) -> ScopedUrl:
    """Resolve and validate a link or redirect against an approved target.

    Relative candidates are resolved using `base_url` when supplied. The base
    URL is itself validated before it is trusted.
    """
    if base_url is None:
        safe_base = target.normalized_url
    else:
        safe_base = _validate_absolute_url(
            target,
            base_url,
            resolver=resolver,
        ).url

    absolute_url = urljoin(safe_base, candidate)

    return _validate_absolute_url(
        target,
        absolute_url,
        resolver=resolver,
    )
