from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web import conversational_views
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


def test_conversation_parser_canonicalizes_bare_targets():
    target = extract_target("scan 10.0.0.143:8010")

    assert target == "http://10.0.0.143:8010/"
    assert canonical_target("HTTP://10.0.0.143:8010") == target
    assert extract_port("scan port 443", None) == 443
    assert extract_profile("run a SAFE check") == "passive"


def test_groq_prompt_sanitizer_never_sends_raw_private_target_or_secret():
    sanitized = _sanitize_for_groq(
        "Scan http://10.0.0.143:8010/path with gsk_example_secret_value_123456"
    )

    assert "10.0.0.143" not in sanitized
    assert "8010/path" not in sanitized
    assert "gsk_example" not in sanitized
    assert "[AUTHORIZED_TARGET]" in sanitized
    assert "[SECRET]" in sanitized


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
def test_root_is_the_conversational_workspace(client, settings):
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
    assert "Approval required" in content
    assert "Remediation guidance" in content
    assert "Technical and audit details" in content
    assert "conversation.js" in content


@pytest.mark.django_db
def test_workspace_message_requires_authentication(client):
    response = client.post("/workspace/message/", {"message": "scan 10.0.0.1:80"})

    assert response.status_code == 302
    assert "/login/" in response["Location"]
