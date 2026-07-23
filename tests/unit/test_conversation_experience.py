from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from vulnhunter.web.conversation_service import deterministic_intent, interpret_request


ROOT = Path(__file__).resolve().parents[2]


def test_ordinary_question_stays_in_chat_instead_of_starting_scan(settings):
    settings.VULNHUNTER_GROQ_ENABLED = False

    result = interpret_request(
        "What link should I use?",
        available_profiles=("passive",),
    )

    assert result.intent == "chat"
    assert result.target is None
    assert result.assistant_copy
    assert "controlled target" in result.assistant_copy.lower()


def test_groq_chat_copy_is_used_without_turning_question_into_scan(settings):
    settings.VULNHUNTER_GROQ_ENABLED = True
    advisory = json.dumps(
        {
            "intent": "chat",
            "message": "The active workspace link is shown with the current assessment.",
            "recommended_profile": None,
        }
    )

    with patch(
        "vulnhunter.web.conversation_service._groq_advisory",
        return_value=(advisory, "mocked Groq advisory"),
    ):
        result = interpret_request(
            "Where can I find the link?",
            available_profiles=("passive",),
        )

    assert result.intent == "chat"
    assert result.provider == "groq"
    assert result.assistant_copy == (
        "The active workspace link is shown with the current assessment."
    )


def test_natural_progress_questions_are_status_requests():
    for message in (
        "What is it doing now?",
        "Has it started?",
        "Why is approval still pending?",
        "How long has it been running?",
    ):
        assert deterministic_intent(message) == "status"


def test_conversation_template_keeps_history_and_details_progressive():
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(
        encoding="utf-8"
    )

    assert "data-history-toggle" in template
    assert "data-history-panel hidden" in template
    assert "data-run-live-copy" in template
    assert '<details data-section="summary">' in template
    assert '<details data-section="summary" open>' not in template


def test_conversation_scroll_respects_manual_reading_position():
    script = (
        ROOT / "vulnhunter/web/static/web/conversation-autoscroll.js"
    ).read_text(encoding="utf-8")

    assert "followingLatest" in script
    assert "distanceFromBottom" in script
    assert "if (!force && !followingLatest) return false" in script
    assert "VulnHunterConversationScroll" in script


def test_conversation_ui_has_elapsed_thinking_and_contextual_answers():
    script = (ROOT / "vulnhunter/web/static/web/conversation.js").read_text(
        encoding="utf-8"
    )

    assert "updateBusyCopy" in script
    assert "Checking the active workspace" in script
    assert "The controlled target for the active assessment is" in script
    assert "announceRunProgress" in script
    assert "confirmedRuns" in script
