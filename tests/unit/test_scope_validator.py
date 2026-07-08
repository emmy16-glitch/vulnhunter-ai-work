"""Tests for strict laboratory target validation."""

from collections.abc import Iterable

import pytest

from vulnhunter.exceptions import ScopeValidationError
from vulnhunter.scope.validator import validate_target


def resolver_returning(*addresses: str):
    """Create a deterministic resolver for tests."""

    def resolve(_: str) -> Iterable[str]:
        return addresses

    return resolve


def test_accepts_ipv4_loopback() -> None:
    target = validate_target("http://127.0.0.1:8000/")

    assert target.hostname == "127.0.0.1"
    assert target.port == 8000
    assert target.resolved_addresses == ("127.0.0.1",)


def test_accepts_private_ipv4_address() -> None:
    target = validate_target("http://192.168.100.20/app/")

    assert target.path == "/app/"
    assert target.resolved_addresses == ("192.168.100.20",)


def test_accepts_private_lab_hostname() -> None:
    target = validate_target(
        "https://lab.internal/security/",
        resolver=resolver_returning("10.10.10.5"),
    )

    assert target.hostname == "lab.internal"
    assert target.port == 443
    assert target.resolved_addresses == ("10.10.10.5",)


def test_rejects_public_ip_address() -> None:
    with pytest.raises(
        ScopeValidationError,
        match="Public Internet addresses are prohibited",
    ):
        validate_target("https://8.8.8.8/")


def test_rejects_link_local_metadata_address() -> None:
    with pytest.raises(
        ScopeValidationError,
        match="Link-local and metadata addresses are prohibited",
    ):
        validate_target("http://169.254.169.254/")


def test_rejects_mixed_private_and_public_dns_results() -> None:
    with pytest.raises(
        ScopeValidationError,
        match="Public Internet addresses are prohibited",
    ):
        validate_target(
            "https://mixed.lab/",
            resolver=resolver_returning(
                "10.0.0.5",
                "8.8.8.8",
            ),
        )


def test_rejects_unsupported_scheme() -> None:
    with pytest.raises(
        ScopeValidationError,
        match="Only http:// and https://",
    ):
        validate_target("ftp://127.0.0.1/")


def test_rejects_embedded_credentials() -> None:
    with pytest.raises(
        ScopeValidationError,
        match="Credentials must not be embedded",
    ):
        validate_target("http://admin:password@127.0.0.1/")


def test_rejects_encoded_path_traversal() -> None:
    with pytest.raises(
        ScopeValidationError,
        match="Dot-segment path traversal",
    ):
        validate_target("http://127.0.0.1/app/%2e%2e/admin")


def test_normalizes_repeated_path_slashes() -> None:
    target = validate_target("http://127.0.0.1:8080/app//status/")

    assert target.normalized_url == ("http://127.0.0.1:8080/app/status/")


def test_rejects_query_strings_in_scope_definition() -> None:
    with pytest.raises(
        ScopeValidationError,
        match="Query strings are not permitted",
    ):
        validate_target("http://127.0.0.1/search?q=test")


def test_rejects_documentation_only_address() -> None:
    """Special-use documentation ranges are not approved lab networks."""
    with pytest.raises(
        ScopeValidationError,
        match="outside the explicitly allowed laboratory networks",
    ):
        validate_target(
            "https://documentation.lab/",
            resolver=resolver_returning("203.0.113.10"),
        )


def test_accepts_ipv6_loopback() -> None:
    target = validate_target("http://[::1]:8000/")

    assert target.hostname == "::1"
    assert target.port == 8000
    assert target.resolved_addresses == ("::1",)
