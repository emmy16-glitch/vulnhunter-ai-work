from __future__ import annotations

import pytest


@pytest.mark.django_db
def test_source_hunt_page_renders_for_assessment_operator_and_is_hidden_from_reviewer(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model
    from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

    from vulnhunter.governance.service import bootstrap_administrator, create_identity
    from vulnhunter.web.models import WebUserMapping
    from vulnhunter.web.templatetags.vh_navigation import canonical_navigation

    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_GROQ_ENABLED = False
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

    governance = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance,
        reviewer_id="source-admin",
        display_name="Source Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    create_identity(
        governance,
        actor_id="source-admin",
        actor_secret=ADMIN_SECRET,
        reviewer_id="source-operator",
        display_name="Source Operator",
        secret="operator-secret-1234",
        roles=("reviewer",),
        now=NOW,
    )

    User = get_user_model()
    operator = User.objects.create_user(username="source-operator-web", password="password-1234")
    WebUserMapping.objects.create(
        user=operator,
        governance_identity_id="source-admin",
        product_roles=["campaign-operator"],
    )
    reviewer = User.objects.create_user(username="source-reviewer-web", password="password-1234")
    WebUserMapping.objects.create(
        user=reviewer,
        governance_identity_id="source-operator",
        product_roles=["reviewer"],
    )

    client.force_login(operator)
    response = client.get("/source-hunt/")

    assert response.status_code == 200
    assert b"Groq-only source analysis" in response.content
    assert b'name="approve_remote_processing"' in response.content
    assert b"Groq source analysis is currently gated" in response.content
    assert "Source Hunt" in {str(item["label"]) for item in canonical_navigation(operator)}

    client.force_login(reviewer)
    denied = client.get("/source-hunt/")

    assert denied.status_code == 403
    assert "Source Hunt" not in {str(item["label"]) for item in canonical_navigation(reviewer)}
