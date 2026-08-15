from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.web.conversational_authorization import (
    ConversationalAuthorizationError,
    prepare_conversational_authorization,
)

_NOW = datetime(2026, 8, 15, 6, 0, tzinfo=UTC)


def _private_resolver(_hostname: str) -> tuple[str, ...]:
    return ("10.20.30.40",)


def _public_resolver(_hostname: str) -> tuple[str, ...]:
    return ("8.8.8.8",)


def test_exact_private_target_authorization_is_reused_until_expiry(tmp_path):
    store = AuthorizationStore.from_path(tmp_path / "authorizations.db")

    first = prepare_conversational_authorization(
        target_url="https://private-lab.example/app",
        evidence_reference="owned staging environment",
        identity_id="operator-1",
        username="operator",
        authorization_store=store,
        resolver=_private_resolver,
        now=_NOW,
    )
    second = prepare_conversational_authorization(
        target_url="https://private-lab.example/app",
        evidence_reference="same owned staging environment",
        identity_id="operator-1",
        username="operator",
        authorization_store=store,
        resolver=_private_resolver,
        now=_NOW + timedelta(hours=1),
    )

    assert first.reused is False
    assert second.reused is True
    assert second.authorization_id == first.authorization_id
    assert second.target == first.target
    assert len(store.list(limit=20)) == 1


def test_expired_private_target_authorization_is_not_reused(tmp_path):
    store = AuthorizationStore.from_path(tmp_path / "authorizations.db")

    first = prepare_conversational_authorization(
        target_url="https://private-lab.example/app",
        evidence_reference="owned staging environment",
        identity_id="operator-1",
        username="operator",
        authorization_store=store,
        resolver=_private_resolver,
        now=_NOW,
    )
    second = prepare_conversational_authorization(
        target_url="https://private-lab.example/app",
        evidence_reference="renewed authorization after expiry",
        identity_id="operator-1",
        username="operator",
        authorization_store=store,
        resolver=_private_resolver,
        now=_NOW + timedelta(hours=13),
    )

    assert second.reused is False
    assert second.authorization_id != first.authorization_id
    assert len(store.list(limit=20)) == 2


def test_chat_cannot_issue_authorization_for_public_target(tmp_path):
    store = AuthorizationStore.from_path(tmp_path / "authorizations.db")

    with pytest.raises(ConversationalAuthorizationError, match="Public targets cannot be authorized"):
        prepare_conversational_authorization(
            target_url="https://public.example/",
            evidence_reference="not sufficient for public target",
            identity_id="operator-1",
            username="operator",
            authorization_store=store,
            resolver=_public_resolver,
            now=_NOW,
        )

    assert store.list(limit=20) == ()
