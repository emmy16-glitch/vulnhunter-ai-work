from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client


@pytest.mark.django_db
def test_public_consent_endpoint_requires_authentication() -> None:
    response = Client().post(
        "/workspace/public-consent/verify/",
        {"target_url": "https://public.test/"},
    )

    assert response.status_code == 302
    assert "/login/" in response["Location"]


@pytest.mark.django_db
def test_public_consent_endpoint_returns_passive_authorization(monkeypatch) -> None:
    user = get_user_model().objects.create_user(
        username="public-consent-web",
        password="safe-pass-1234",
    )
    client = Client()
    client.force_login(user)
    expires_at = datetime(2026, 8, 26, 12, tzinfo=UTC)
    result = SimpleNamespace(
        record=SimpleNamespace(
            authorization_id="auth-public-web",
            target_url="https://public.test/community/",
            expires_at=expires_at,
        ),
        passive_only=True,
        consent_url="https://public.test/.well-known/vulnhunter-consent.json",
        consent_sha256="a" * 64,
    )

    monkeypatch.setattr(
        "vulnhunter.web.public_consent_views.authorized_actor",
        lambda *_args, **_kwargs: object(),
    )
    with patch(
        "vulnhunter.web.public_consent_views.create_public_consent_authorization",
        return_value=result,
    ) as verifier:
        response = client.post(
            "/workspace/public-consent/verify/",
            {
                "target_url": "https://public.test/community/",
                "challenge_token": "consent-token-0123456789",
                "owner": "Public Test Owner",
                "approved_by": "Browser Approver",
                "purpose": "Bounded passive mapping",
                "expires_at": "2026-08-26T12:00:00+00:00",
            },
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["authorization"]["id"] == "auth-public-web"
    assert payload["authorization"]["passive_only"] is True
    assert "passive mapping only" in payload["message"]
    verifier.assert_called_once()
