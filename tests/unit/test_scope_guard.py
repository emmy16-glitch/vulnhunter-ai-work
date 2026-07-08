"""Tests for links and redirects derived from approved targets."""

from collections.abc import Iterable

import pytest

from vulnhunter.exceptions import ScopeValidationError, ScopeViolationError
from vulnhunter.scope import validate_scoped_url, validate_target


def resolver_returning(*addresses: str):
    """Create a deterministic resolver for scope tests."""

    def resolve(_: str) -> Iterable[str]:
        return addresses

    return resolve


def create_lab_target():
    """Create a hostname-based target without using external DNS."""
    return validate_target(
        "http://lab.internal:8000/app/",
        resolver=resolver_returning("10.0.0.5"),
    )


def test_accepts_relative_url_inside_path_boundary() -> None:
    target = create_lab_target()

    result = validate_scoped_url(
        target,
        "settings?mode=summary#section",
        base_url="http://lab.internal:8000/app/dashboard/",
        resolver=resolver_returning("10.0.0.5"),
    )

    assert result.url == ("http://lab.internal:8000/app/dashboard/settings?mode=summary")
    assert result.query == "mode=summary"


def test_accepts_absolute_url_inside_scope() -> None:
    target = create_lab_target()

    result = validate_scoped_url(
        target,
        "http://lab.internal:8000/app/profile",
        resolver=resolver_returning("10.0.0.5"),
    )

    assert result.path == "/app/profile"


def test_rejects_different_hostname() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="leave the approved hostname",
    ):
        validate_scoped_url(
            target,
            "http://other.internal:8000/app/",
            resolver=resolver_returning("10.0.0.5"),
        )


def test_rejects_different_port() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="change the approved port",
    ):
        validate_scoped_url(
            target,
            "http://lab.internal:9000/app/",
            resolver=resolver_returning("10.0.0.5"),
        )


def test_rejects_scheme_change() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="change the approved scheme",
    ):
        validate_scoped_url(
            target,
            "https://lab.internal:8000/app/",
            resolver=resolver_returning("10.0.0.5"),
        )


def test_rejects_path_outside_boundary() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="leave the approved path boundary",
    ):
        validate_scoped_url(
            target,
            "/admin/",
            resolver=resolver_returning("10.0.0.5"),
        )


def test_rejects_path_prefix_confusion() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="leave the approved path boundary",
    ):
        validate_scoped_url(
            target,
            "/application/",
            resolver=resolver_returning("10.0.0.5"),
        )


def test_rejects_encoded_path_traversal() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="Dot-segment path traversal",
    ):
        validate_scoped_url(
            target,
            "/app/%2e%2e/admin",
            resolver=resolver_returning("10.0.0.5"),
        )


def test_rejects_embedded_credentials() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="Credentials are not permitted",
    ):
        validate_scoped_url(
            target,
            "http://user:password@lab.internal:8000/app/",
            resolver=resolver_returning("10.0.0.5"),
        )


def test_rejects_dns_rebinding_to_new_address() -> None:
    target = create_lab_target()

    with pytest.raises(
        ScopeViolationError,
        match="DNS resolution changed",
    ):
        validate_scoped_url(
            target,
            "/app/profile",
            resolver=resolver_returning("10.0.0.99"),
        )


def test_accepts_ipv6_loopback_url() -> None:
    target = validate_target("http://[::1]:8000/app/")

    result = validate_scoped_url(
        target,
        "/app/status",
    )

    assert result.url == "http://[::1]:8000/app/status"
    assert result.resolved_addresses == ("::1",)


def test_translates_resolver_failure_to_scope_violation() -> None:
    target = create_lab_target()

    def failing_resolver(_: str) -> Iterable[str]:
        raise ScopeValidationError("Hostname could not be resolved: lab.internal")

    with pytest.raises(
        ScopeViolationError,
        match="Hostname could not be resolved",
    ):
        validate_scoped_url(
            target,
            "/app/profile",
            resolver=failing_resolver,
        )
