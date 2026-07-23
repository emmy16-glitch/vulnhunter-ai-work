from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpResponse

from vulnhunter.web import (
    conversation_approval_views,
    conversational_views,
    dashboard_dispatch_views,
)
from vulnhunter.web.conversation_service import (
    _sanitize_for_groq,
    canonical_target,
    extract_port,
    extract_profile,
    extract_target,
    interpret_request,
)
from vulnhunter.web.models import WebUserMapping


def test_conversation_parser_extracts_authoritative_target_port_and_profile(settings):
    settings.VULNHUNTER_GROQ_ENABLED = False

    result = interpret_request(
        "Please scan http://10.0.0.143:8010 safely with the passive profile",
        available_profiles=("passive",),
    )

    assert result.intent == "scan"
    assert result.target == "http://10.0.0.143:8010/"
    assert result.protocol == "http"
    assert result.port == 8010
    assert result.profile == "passive"
    assert result.provider == "deterministic"


def test_conversation_parser_canonicalizes_bare_and_ipv6_targets():
    target = extract_target("scan 10.0.0.143:8010")

    assert target == "http://10.0.0.143:8010/"
    assert canonical_target("HTTP://10.0.0.143:8010") == target
    assert canonical_target("HTTP://[FD00::1]:8010") == "http://[fd00::1]:8010/"
    assert extract_target("scan [fd00::1]:8010") == "http://[fd00::1]:8010/"
    assert extract_port("scan port 443", None) == 443
    assert extract_profile("run a SAFE check") == "passive"


def test_groq_prompt_sanitizer_removes_targets_and_protected_values():
    sanitized = _sanitize_for_groq(
        "Scan internal.lab:8010 and http://10.0.0.143:8010/path\n"
        "Authorization: Bearer abc.def.ghi\n"
        "Cookie: session_id=private-cookie\n"
        "Contact admin@example.com with password=super-secret\n"
        "Card 4111 1111 1111 1111 and gsk_example_secret_value_123456"
    )

    for protected in (
        "internal.lab",
        "10.0.0.143",
        "8010/path",
        "abc.def.ghi",
        "private-cookie",
        "admin@example.com",
        "super-secret",
        "4111 1111 1111 1111",
        "gsk_example",
    ):
        assert protected not in sanitized
    assert "[AUTHORIZED_TARGET]" in sanitized
    assert "[REDACTED]" in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_PAYMENT_DATA]" in sanitized


def test_remote_advisory_cannot_turn_a_scan_request_into_cancellation(settings):
    settings.VULNHUNTER_GROQ_ENABLED = True
    advisory = json.dumps(
        {
            "intent": "cancel",
            "message": "Cancel the assessment.",
            "recommended_profile": "passive",
        }
    )

    with patch(
        "vulnhunter.web.conversation_service._groq_advisory",
        return_value=(advisory, "test advisory"),
    ):
        result = interpret_request(
            "Scan 10.0.0.143:8010 safely",
            available_profiles=("passive",),
        )

    assert result.intent == "scan"
    assert result.profile == "passive"


def test_conversation_payload_reads_persisted_finding_and_artifact_mappings():
    finding = conversational_views._safe_finding(
        {
            "evidence_id": "finding-observation-1",
            "title": "Missing security header",
            "severity": "low",
            "verification": "validated",
            "target_reference": "target-reference",
        }
    )
    artifact = conversational_views._safe_artifact(
        {
            "filename": "evidence.jsonl",
            "type": "jsonl",
            "size": 321,
            "checksum": "a" * 64,
        }
    )

    assert finding == {
        "title": "Missing security header",
        "severity": "low",
        "verification": "validated",
        "target": "target-reference",
        "finding_id": "finding-observation-1",
    }
    assert artifact == {
        "filename": "evidence.jsonl",
        "type": "jsonl",
        "size": 321,
        "checksum": "a" * 64,
    }


@pytest.mark.django_db
def test_conversation_approval_rejects_the_requester(client):
    user = get_user_model().objects.create_user(
        username="operator",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="operator-identity")
    )
    pending = SimpleNamespace(
        requested_by="operator-identity",
        run_id="run-test",
    )
    store = SimpleNamespace(get=lambda _request_id: pending)

    with (
        patch.object(conversation_approval_views, "_actor", return_value=actor),
        patch.object(conversation_approval_views, "_approval_store", return_value=store),
    ):
        response = client.post(
            "/workspace/approve/",
            {
                "request_id": "approval-test",
                "plan_digest": "a" * 64,
                "reason": "Approved for this exact plan.",
            },
        )

    assert response.status_code == 409
    assert "cannot approve" in response.json()["detail"]


@pytest.mark.django_db
def test_root_is_the_conversational_workspace_for_campaign_operator(client, settings):
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="vulnhunter",
        password="long-test-password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="vulnhunter-user",
        product_roles=["campaign-operator"],
    )
    client.force_login(user)
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="vulnhunter-user"),
        product_roles=("campaign-operator",),
    )

    with (
        patch.object(conversational_views, "_actor", return_value=actor),
        patch.object(conversational_views, "_recent_runs", return_value=()),
    ):
        response = client.get("/")

    content = response.content.decode("utf-8")
    assert response.status_code == 200
    assert "VulnHunter Workspace" in content
    assert "data-conversation-form" in content
    assert "Independent approval required" in content
    assert "Open approval centre" in content
    assert "Remediation guidance" in content
    assert "Technical and audit details" in content
    assert "conversation.js" in content


@pytest.mark.django_db
def test_root_preserves_dashboard_for_non_scanning_roles(client, settings):
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="reviewer",
        password="long-test-password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="reviewer-identity",
        product_roles=["reviewer"],
    )
    client.force_login(user)

    with patch.object(
        dashboard_dispatch_views.views,
        "dashboard_view",
        return_value=HttpResponse("governed dashboard"),
    ) as dashboard:
        response = client.get("/")

    assert response.status_code == 200
    assert response.content == b"governed dashboard"
    dashboard.assert_called_once()


@pytest.mark.django_db
def test_workspace_message_requires_authentication(client):
    response = client.post("/workspace/message/", {"message": "scan 10.0.0.1:80"})

    assert response.status_code == 302
    assert "/login/" in response["Location"]
