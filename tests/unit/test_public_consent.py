from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

import vulnhunter.authorization.public_consent as public_consent
from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.public_consent import (
    PublicConsentError,
    create_public_consent_authorization,
    has_verified_public_consent,
)
from vulnhunter.authorization.service import validate_scan_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import AuthorizationPolicyError
from vulnhunter.scope import validate_target

NOW = datetime(2026, 8, 19, 12, tzinfo=UTC)
TOKEN = "consent-token-0123456789"


def resolver(hostname: str) -> tuple[str, ...]:
    assert hostname == "example.test"
    return ("93.184.216.34",)


def fetcher(url: str) -> tuple[int, bytes, str]:
    assert url == "https://example.test/.well-known/vulnhunter-consent.json"
    return 200, (f'{{"token":"{TOKEN}"}}').encode(), "application/json"


def limits() -> AuthorizationLimits:
    return AuthorizationLimits(
        maximum_pages=10,
        maximum_depth=1,
        maximum_requests=50,
        minimum_request_delay_seconds=1.0,
    )


def create(store: AuthorizationStore):
    return create_public_consent_authorization(
        target_url="https://example.test/community/",
        challenge_token=TOKEN,
        owner="Example Owner",
        approved_by="Security Approver",
        purpose="Bounded passive mapping",
        expires_at=NOW + timedelta(days=7),
        limits=limits(),
        authorization_store=store,
        resolver=resolver,
        fetcher=fetcher,
        now=NOW,
    )


def test_public_consent_creates_exact_passive_authorization_and_event(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()

    result = create(store)

    assert result.record.target_url == "https://example.test/community/"
    assert result.record.approved_addresses == ("93.184.216.34",)
    assert result.passive_only is True
    assert has_verified_public_consent(store, result.record.authorization_id)
    assert any(
        event.event_type == "public_consent_verified"
        for event in store.list_events(result.record.authorization_id)
    )


def test_public_consent_token_mismatch_fails_closed_without_record(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()

    with pytest.raises(PublicConsentError, match="did not match"):
        create_public_consent_authorization(
            target_url="https://example.test/community/",
            challenge_token="different-token-012345",
            owner="Example Owner",
            approved_by="Security Approver",
            purpose="Bounded passive mapping",
            expires_at=NOW + timedelta(days=7),
            limits=limits(),
            authorization_store=store,
            resolver=resolver,
            fetcher=fetcher,
            now=NOW,
        )

    assert store.list(limit=10) == ()


def test_public_validation_requires_verified_consent_event(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    result = create(store)
    target = validate_target(
        "https://example.test/community/",
        resolver=resolver,
        allow_public=True,
    )

    with pytest.raises(AuthorizationPolicyError, match="explicit consent-enabled"):
        validate_scan_authorization(
            store,
            result.record.authorization_id,
            target,
            maximum_pages=5,
            maximum_depth=1,
            maximum_requests=20,
            request_delay_seconds=1.0,
            now=NOW + timedelta(hours=1),
        )

    decision = validate_scan_authorization(
        store,
        result.record.authorization_id,
        target,
        maximum_pages=5,
        maximum_depth=1,
        maximum_requests=20,
        request_delay_seconds=1.0,
        now=NOW + timedelta(hours=1),
        allow_public=True,
    )
    assert decision.target_url == target.normalized_url


def test_default_fetcher_returns_bounded_response_metadata() -> None:
    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, maximum: int) -> bytes:
            assert maximum == 16_385
            return b'{"token":"ok"}'

    with patch.object(public_consent, "urlopen", return_value=Response()) as opener:
        status, body, content_type = public_consent._default_fetcher(
            "https://example.test/.well-known/vulnhunter-consent.json"
        )

    request = opener.call_args.args[0]
    assert request.get_method() == "GET"
    assert request.get_header("User-agent") == "VulnHunter-public-consent-verifier/1.0"
    assert status == 200
    assert body == b'{"token":"ok"}'
    assert content_type == "application/json"


@pytest.mark.parametrize(
    "failure",
    [
        HTTPError("https://example.test/", 503, "unavailable", {}, None),
        URLError("connection refused"),
        TimeoutError("timed out"),
        OSError("socket failure"),
    ],
)
def test_default_fetcher_translates_network_failures(failure) -> None:
    with patch.object(public_consent, "urlopen", side_effect=failure):
        with pytest.raises(PublicConsentError, match="could not be fetched safely") as error:
            public_consent._default_fetcher("https://example.test/.well-known/vulnhunter-consent.json")

    assert error.value.__cause__ is failure


@pytest.mark.parametrize(
    "addresses, message",
    [
        (("not-an-ip",), "invalid address"),
        (("192.0.2.10",), "globally routable"),
        ((), "did not resolve"),
    ],
)
def test_public_address_filter_rejects_invalid_or_non_global_results(addresses, message) -> None:
    with pytest.raises(PublicConsentError, match=message):
        public_consent._public_addresses(addresses)


def test_challenge_parser_accepts_plaintext_and_rejects_bounded_or_invalid_payloads() -> None:
    public_consent._parse_challenge(
        b"plain-token-012345",
        token="plain-token-012345",
        content_type="text/plain",
    )
    with pytest.raises(PublicConsentError, match="bounded size"):
        public_consent._parse_challenge(b"x" * 16_385, token=TOKEN, content_type="text/plain")
    with pytest.raises(PublicConsentError, match="valid JSON"):
        public_consent._parse_challenge(b"{broken", token=TOKEN, content_type="application/json")


def test_consent_parser_rejects_invalid_utf8_payload() -> None:
    with pytest.raises(PublicConsentError, match="valid UTF-8"):
        public_consent._parse_challenge(b"\xff", token=TOKEN, content_type="text/plain")


@pytest.mark.parametrize(
    "token, message",
    [
        ("short", "16-256"),
        ("consent token with spaces", "non-whitespace"),
    ],
)
def test_consent_creation_rejects_malformed_tokens(tmp_path, token, message) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    with pytest.raises(PublicConsentError, match=message):
        create_public_consent_authorization(
            target_url="https://example.test/community/",
            challenge_token=token,
            owner="Example Owner",
            approved_by="Security Approver",
            purpose="Bounded passive mapping",
            expires_at=NOW + timedelta(days=7),
            limits=limits(),
            authorization_store=store,
            resolver=resolver,
            fetcher=fetcher,
            now=NOW,
        )


def test_consent_creation_rejects_non_https_scope_resolution_and_expiry(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    common = {
        "challenge_token": TOKEN,
        "owner": "Example Owner",
        "approved_by": "Security Approver",
        "purpose": "Bounded passive mapping",
        "expires_at": NOW + timedelta(days=7),
        "limits": limits(),
        "authorization_store": store,
        "resolver": resolver,
        "fetcher": fetcher,
        "now": NOW,
    }
    with pytest.raises(PublicConsentError, match="HTTPS"):
        create_public_consent_authorization(target_url="http://example.test/", **common)
    with pytest.raises(PublicConsentError, match="within 30 days"):
        create_public_consent_authorization(
            target_url="https://example.test/",
            **{**common, "expires_at": NOW + timedelta(days=31)},
        )
    with pytest.raises(PublicConsentError, match="HTTP 200"):
        create_public_consent_authorization(
            target_url="https://example.test/",
            **{**common, "fetcher": lambda _url: (503, b"", "text/plain")},
        )


def test_consent_creation_wraps_scope_validation_errors(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    with pytest.raises(PublicConsentError, match="explicitly allowed"):
        create_public_consent_authorization(
            target_url="https://example.test/",
            challenge_token=TOKEN,
            owner="Example Owner",
            approved_by="Security Approver",
            purpose="Bounded passive mapping",
            expires_at=NOW + timedelta(days=7),
            limits=limits(),
            authorization_store=store,
            resolver=lambda _hostname: ("192.0.2.10",),
            fetcher=fetcher,
            now=NOW,
        )


def test_has_verified_public_consent_rejects_non_public_or_unverifiable_record(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    result = create(store)
    record = result.record
    assert has_verified_public_consent(store, record.authorization_id) is True
    with patch.object(
        store,
        "get",
        return_value=record.model_copy(update={"evidence_reference": None}),
    ):
        assert has_verified_public_consent(store, record.authorization_id) is False
    with patch.object(
        store,
        "get",
        return_value=record.model_copy(update={"target_url": "http://example.test/"}),
    ):
        assert has_verified_public_consent(store, record.authorization_id) is False
