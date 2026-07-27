from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web import conversational_views
from vulnhunter.web.conversation_threads import ThreadSessionProxy, create_thread
from vulnhunter.web.models import ConversationThread, WebUserMapping


class _Workflow:
    def list_authorizations(self, **_kwargs):
        return ()


@pytest.fixture
def workspace_actor():
    return SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="persistent-user"),
        product_roles=("campaign-operator",),
    )


def _map_workspace_user(user, *, governance_identity_id: str = "persistent-user") -> None:
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id=governance_identity_id,
        product_roles=["campaign-operator"],
    )


@pytest.mark.django_db
def test_new_workspace_is_persisted_and_reopenable(client, settings, workspace_actor):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_GROQ_ENABLED = False
    user = get_user_model().objects.create_user(
        username="persistent-user", password="safe-pass-1234"
    )
    _map_workspace_user(user)
    client.force_login(user)

    with (
        patch.object(conversational_views, "_actor", return_value=workspace_actor),
        patch.object(conversational_views, "_recent_runs", return_value=()),
    ):
        opened = client.get("/")
    assert opened.status_code == 200
    thread = ConversationThread.objects.get(owner=user)
    assert str(thread.thread_id) in opened.content.decode("utf-8")

    created = client.post(
        "/workspace/threads/new/",
        {"title": "Website assessment"},
        HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
    )
    assert created.status_code == 201
    second_id = created.json()["thread"]["thread_id"]
    assert ConversationThread.objects.filter(owner=user, thread_id=second_id).exists()

    with (
        patch.object(conversational_views, "_actor", return_value=workspace_actor),
        patch.object(conversational_views, "_recent_runs", return_value=()),
    ):
        reopened = client.get(f"/?thread={thread.thread_id}")
    assert reopened.status_code == 200
    assert 'aria-current="page"' in reopened.content.decode("utf-8")


@pytest.mark.django_db
def test_messages_are_isolated_per_workspace(client, settings, workspace_actor):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_GROQ_ENABLED = False
    user = get_user_model().objects.create_user(username="thread-user", password="safe-pass-1234")
    first = create_thread(owner=user, title="First task")
    second = create_thread(owner=user, title="Second task")
    client.force_login(user)

    with (
        patch.object(conversational_views, "_actor", return_value=workspace_actor),
        patch.object(
            conversational_views.AssessmentWorkflowService,
            "from_settings",
            return_value=_Workflow(),
        ),
    ):
        response = client.post(
            "/workspace/message/",
            {"message": "How do background APK uploads work?"},
            HTTP_X_VULNHUNTER_THREAD=str(first.thread_id),
        )
    assert response.status_code == 200

    first.refresh_from_db()
    second.refresh_from_db()
    first_messages = first.data["vulnhunter_conversation_messages"]
    assert any("background APK uploads" in item["content"] for item in first_messages)
    assert "vulnhunter_conversation_messages" not in second.data


@pytest.mark.django_db
def test_thread_session_proxy_merges_independent_concurrent_keys(django_user_model):
    user = django_user_model.objects.create_user(username="merge-user", password="safe-pass-1234")
    thread = create_thread(owner=user)

    class BaseSession(dict):
        modified = False

    first = ThreadSessionProxy(BaseSession(), thread)
    second = ThreadSessionProxy(BaseSession(), thread)
    first["vulnhunter_conversation_messages"] = [{"role": "user", "content": "APK"}]
    second["vulnhunter_conversation_state"] = {"run_id": "run-1"}

    thread.refresh_from_db()
    assert thread.data["vulnhunter_conversation_messages"][0]["content"] == "APK"
    assert thread.data["vulnhunter_conversation_state"]["run_id"] == "run-1"


def test_workspace_assets_include_thread_routing_and_background_upload_coordinator():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    template = (root / "vulnhunter/web/templates/web/conversation.html").read_text()
    base = (root / "vulnhunter/web/templates/web/base.html").read_text()
    thread_client = (root / "vulnhunter/web/static/web/conversation-thread-client.js").read_text()
    coordinator = (
        root / "vulnhunter/web/static/web/conversation-upload-coordinator.js"
    ).read_text()

    assert "data-thread-id" in template
    assert "data-thread-create" in template
    assert "conversation-thread-client.js" in template
    assert "conversation-upload-coordinator.js" in base
    assert "X-VulnHunter-Thread" in thread_client
    assert "indexedDB.open" in coordinator
    assert "navigator.locks" in coordinator
    assert "reconcileOffset" in coordinator
    assert "BroadcastChannel" in coordinator


@pytest.mark.django_db
def test_legacy_session_conversation_is_migrated_once(client, settings, workspace_actor):
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(username="legacy-user", password="safe-pass-1234")
    _map_workspace_user(user)
    client.force_login(user)
    session = client.session
    session["vulnhunter_conversation_messages"] = [
        {"role": "user", "kind": "text", "content": "Keep this APK discussion", "timestamp": "now"}
    ]
    session["vulnhunter_conversation_state"] = {"target": "http://127.0.0.1:8010/"}
    session.save()

    with (
        patch.object(conversational_views, "_actor", return_value=workspace_actor),
        patch.object(conversational_views, "_recent_runs", return_value=()),
    ):
        response = client.get("/")
    assert response.status_code == 200
    thread = ConversationThread.objects.get(owner=user)
    assert (
        thread.data["vulnhunter_conversation_messages"][0]["content"] == "Keep this APK discussion"
    )
    assert thread.data["vulnhunter_conversation_state"]["target"] == "http://127.0.0.1:8010/"
    refreshed_session = client.session
    assert "vulnhunter_conversation_messages" not in refreshed_session
    assert "vulnhunter_conversation_state" not in refreshed_session


@pytest.mark.django_db
def test_user_cannot_open_another_users_workspace(client, settings):
    settings.ALLOWED_HOSTS = ["testserver"]
    owner = get_user_model().objects.create_user(username="owner", password="safe-pass-1234")
    intruder = get_user_model().objects.create_user(username="intruder", password="safe-pass-1234")
    thread = create_thread(owner=owner, title="Private APK work")
    client.force_login(intruder)

    response = client.get(
        f"/workspace/threads/?thread={thread.thread_id}",
        HTTP_ACCEPT="application/json",
    )

    assert response.status_code == 404
    assert "unavailable" in response.json()["detail"]
