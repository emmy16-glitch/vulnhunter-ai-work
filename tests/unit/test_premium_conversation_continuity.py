from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web import conversational_views
from vulnhunter.web.conversation_service import InterpretedRequest
from vulnhunter.web.conversation_threads import create_thread

ROOT = Path(__file__).resolve().parents[2]
MIDDLEWARE = ROOT / "vulnhunter" / "web" / "middleware.py"
INTERACTION = ROOT / "vulnhunter" / "web" / "static" / "web" / "premium-interaction.js"
CONTINUITY = ROOT / "vulnhunter" / "web" / "static" / "web" / "conversation-premium-continuity.js"
CONTINUITY_CSS = ROOT / "vulnhunter" / "web" / "static" / "web" / "conversation-premium-continuity.css"
AUTOSCROLL = ROOT / "vulnhunter" / "web" / "static" / "web" / "conversation-autoscroll.js"


class _Workflow:
    def list_authorizations(self, **_kwargs):
        return ()


def _actor():
    return SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="premium-conversation"),
        product_roles=("campaign-operator",),
    )


def _interpreted() -> InterpretedRequest:
    return InterpretedRequest(
        intent="chat",
        target=None,
        protocol=None,
        port=None,
        profile=None,
        evidence_reference=None,
        assistant_copy="Stable evidence-grounded response.",
        provider="deterministic",
        provider_detail="local",
        model=None,
        reasoning_effort="medium",
    )


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.mark.django_db
def test_message_receipt_replays_timeout_after_success_without_duplicate_logical_message(
    client, settings
):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_GROQ_ENABLED = False
    settings.VULNHUNTER_HUGGINGFACE_ENABLED = False
    user = get_user_model().objects.create_user(
        username="premium-message-receipt",
        password="safe-pass-1234",
    )
    thread = create_thread(owner=user)
    client.force_login(user)
    message_id = "msg:timeout-after-success-0001"

    with (
        patch.object(conversational_views, "_actor", return_value=_actor()),
        patch.object(
            conversational_views.AssessmentWorkflowService,
            "from_settings",
            return_value=_Workflow(),
        ),
        patch.object(conversational_views, "interpret_request", return_value=_interpreted()),
    ):
        first = client.post(
            "/workspace/message/",
            {
                "message": "Explain the selected evidence",
                "reasoning_effort": "medium",
                "client_message_id": message_id,
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )
        thread.refresh_from_db()
        first_messages = list(thread.data["vulnhunter_conversation_messages"])
        second = client.post(
            "/workspace/message/",
            {
                "message": "Explain the selected evidence",
                "reasoning_effort": "medium",
                "client_message_id": message_id,
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    thread.refresh_from_db()
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert second.headers["X-VulnHunter-Message-Replayed"] == "true"
    assert second.headers["X-VulnHunter-Message-Receipt"] == message_id
    assert thread.data["vulnhunter_conversation_messages"] == first_messages


@pytest.mark.django_db
def test_invalid_message_receipt_identifier_fails_before_conversation_execution(client, settings):
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="invalid-message-receipt",
        password="safe-pass-1234",
    )
    thread = create_thread(owner=user)
    client.force_login(user)

    with patch.object(conversational_views, "interpret_request") as interpret:
        response = client.post(
            "/workspace/message/",
            {"message": "Do not execute", "client_message_id": "bad id with spaces"},
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    assert response.status_code == 400
    assert "receipt identifier is invalid" in response.json()["detail"]
    interpret.assert_not_called()


def test_message_receipts_are_bounded_and_owned_by_thread_middleware() -> None:
    middleware = _text(MIDDLEWARE)

    assert '_SESSION_MESSAGE_RECEIPTS = "vulnhunter_conversation_message_receipts"' in middleware
    assert "_MAX_MESSAGE_RECEIPTS = 64" in middleware
    assert 'request.path != "/workspace/message/"' in middleware
    assert 'response["X-VulnHunter-Message-Replayed"] = "true"' in middleware
    assert "while len(receipts) > _MAX_MESSAGE_RECEIPTS" in middleware
    assert "request.session[_SESSION_MESSAGE_RECEIPTS] = receipts" in middleware


def test_shared_interaction_owner_loads_one_conversation_continuity_layer() -> None:
    interaction = _text(INTERACTION)

    assert "loadConversationContinuity" in interaction
    assert 'document.querySelector("[data-conversation-workspace]")' in interaction
    assert '"conversation-premium-continuity.js"' in interaction
    assert '"conversation-premium-continuity.css"' in interaction
    assert "data-conversation-premium-continuity" in interaction


def test_send_continuity_uses_stable_client_identity_and_keeps_composer_editable() -> None:
    javascript = _text(CONTINUITY)

    assert 'body.set("client_message_id", activeSend.id)' in javascript
    assert "window.crypto?.randomUUID" in javascript
    assert 'markArticle(article, "sending", "Sending…")' in javascript
    assert 'markArticle(activeSend.article, "accepted", "Sent")' in javascript
    assert '"Connection interrupted before the response was confirmed."' in javascript
    assert 'button.textContent = "Retry"' in javascript
    assert "retrySeed" in javascript
    assert "if (!activeSend || !input.disabled) return" in javascript
    assert "input.disabled = false" in javascript
    assert "event.stopImmediatePropagation" not in javascript


def test_complete_server_response_is_stabilized_instead_of_decorative_word_streaming() -> None:
    javascript = _text(CONTINUITY)

    assert "stableAssistantMessages.push(payload.message.content)" in javascript
    assert "stableCopies.set(copy, expected)" in javascript
    assert "copy.textContent = expected" in javascript
    assert "setInterval" not in javascript


def test_autoscroll_remains_reader_controlled_with_jump_to_latest() -> None:
    javascript = _text(AUTOSCROLL)

    assert "followingLatest = distanceFromBottom() <= bottomThreshold" in javascript
    assert "if (!force && !followingLatest) return false" in javascript
    assert 'jump.textContent = unreadMessages > 0 ? `↓ ${unreadMessages} new` : "↓ Latest"' in javascript
    assert 'feed.addEventListener("wheel", pauseFollowing' in javascript
    assert 'feed.addEventListener("touchstart", pauseFollowing' in javascript
    assert "if (!followingLatest && addedMessages > 0) unreadMessages += addedMessages" in javascript


def test_delivery_states_have_accessible_reduced_motion_safe_targets() -> None:
    css = _text(CONTINUITY_CSS)

    assert ".vh-message-delivery" in css
    assert ".is-send-failed" in css
    assert ".vh-message-retry" in css
    assert "min-width: 44px" in css
    assert "min-height: 44px" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
