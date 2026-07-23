from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import ScopeValidationError
from vulnhunter.scope import validate_target
from vulnhunter.web import conversational_views
from vulnhunter.web.assessment_workflow import load_nuclei_authorization
from vulnhunter.web.conversation_service import interpret_request
from vulnhunter.web.conversational_authorization import (
    ConversationalAuthorizationError,
    prepare_conversational_authorization,
)


def test_pasted_website_and_custom_port_are_recognized(settings):
    settings.VULNHUNTER_GROQ_ENABLED = False

    request = interpret_request(
        "https://example.com:54321/login",
        available_profiles=("passive",),
    )

    assert request.intent == "scan"
    assert request.target == "https://example.com:54321/login"
    assert request.port == 54321
    assert request.protocol == "https"


def test_bare_website_is_treated_as_a_scan_target(settings):
    settings.VULNHUNTER_GROQ_ENABLED = False

    request = interpret_request(
        "Please check example.com",
        available_profiles=("passive",),
    )

    assert request.intent == "scan"
    assert request.target == "http://example.com:80/"


def test_public_resolution_requires_explicit_opt_in():
    def resolver(_hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    with pytest.raises(ScopeValidationError, match="Public Internet"):
        validate_target("https://example.com/", resolver=resolver)

    target = validate_target(
        "https://example.com:8443/login",
        resolver=resolver,
        allow_public=True,
    )
    assert target.port == 8443
    assert target.resolved_addresses == ("93.184.216.34",)


def test_public_chat_authorization_requires_evidence(tmp_path):
    store = AuthorizationStore(tmp_path / "authorization.db")

    def resolver(_hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    with pytest.raises(ConversationalAuthorizationError, match="evidence reference"):
        prepare_conversational_authorization(
            target_url="https://example.com:8443/login",
            evidence_reference=None,
            identity_id="vulnhunter-user",
            username="vulnhunter",
            authorization_store=store,
            resolver=resolver,
            now=datetime(2026, 7, 23, 18, 0, tzinfo=UTC),
        )


def test_chat_authorization_accepts_any_valid_http_port(tmp_path):
    store = AuthorizationStore(tmp_path / "authorization.db")
    instant = datetime(2026, 7, 23, 18, 0, tzinfo=UTC)

    prepared = prepare_conversational_authorization(
        target_url="http://10.0.0.7:65535/",
        evidence_reference=None,
        identity_id="vulnhunter-user",
        username="vulnhunter",
        authorization_store=store,
        now=instant,
    )

    record, engagement = load_nuclei_authorization(store, prepared.authorization_id)
    assert prepared.port == 65535
    assert prepared.address_class == "private"
    assert record.port == 65535
    assert engagement.approved_ports == (65535,)
    assert engagement.private_network_approved is True


def test_public_chat_authorization_records_exact_url_and_port(tmp_path):
    store = AuthorizationStore(tmp_path / "authorization.db")

    def resolver(_hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    instant = datetime(2026, 7, 23, 18, 0, tzinfo=UTC)

    prepared = prepare_conversational_authorization(
        target_url="https://example.com:8443/login",
        evidence_reference="Bug bounty scope page BB-2026-17",
        identity_id="vulnhunter-user",
        username="vulnhunter",
        authorization_store=store,
        resolver=resolver,
        now=instant,
    )

    record, engagement = load_nuclei_authorization(store, prepared.authorization_id)
    assert record.hostname == "example.com"
    assert record.port == 8443
    assert record.evidence_reference == "Bug bounty scope page BB-2026-17"
    assert engagement.approved_ports == (8443,)
    assert engagement.private_network_approved is False


def test_authorization_keeps_the_previously_pasted_target_when_evidence_is_a_url():
    selected = conversational_views._target_for_request(
        intent="authorize",
        interpreted_target="https://bug-bounty.example/scope",
        stored_target="https://target.example:8443/login",
    )

    assert selected == "https://target.example:8443/login"
