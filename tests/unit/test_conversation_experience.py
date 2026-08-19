from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from vulnhunter.web.conversation_service import (
    deterministic_intent,
    interpret_request,
)
from vulnhunter.web.mobile_conversation_state import mobile_chat_reply

ROOT = Path(__file__).resolve().parents[2]


def test_ordinary_question_reports_high_reasoning_unavailable_without_starting_scan(settings):
    settings.VULNHUNTER_GROQ_ENABLED = False

    result = interpret_request(
        "What link should I use?",
        available_profiles=("passive",),
    )

    assert result.intent == "chat"
    assert result.target is None
    assert result.provider == "auto"
    assert result.model is None
    assert result.reasoning_effort == "high"
    assert result.assistant_copy
    assert "couldn't complete that response" in result.assistant_copy
    assert "Groq" not in result.assistant_copy
    assert "Gemini" not in result.assistant_copy
    assert "Ollama" not in result.assistant_copy


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
    assert result.provider == "auto"
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
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(encoding="utf-8")

    assert "data-history-toggle" in template
    assert "data-conversation-stop" in template
    assert "vh-activity-template" in template
    assert "data-activity-entry" in template
    assert "data-history-panel hidden" in template
    assert "data-run-live-copy" in template
    assert '<details data-section="summary">' in template
    assert '<details data-section="summary" open>' not in template


def test_conversation_scroll_respects_manual_reading_position():
    script = (ROOT / "vulnhunter/web/static/web/conversation-autoscroll.js").read_text(
        encoding="utf-8"
    )

    assert "followingLatest" in script
    assert "distanceFromBottom" in script
    assert "if (!force && !followingLatest) return false" in script
    assert "VulnHunterConversationScroll" in script


def test_desktop_browser_acceptance_covers_live_sse_lifecycle():
    script = (ROOT / "tests/ui/conversation_e2e.cjs").read_text(encoding="utf-8")

    assert "data-activity-entry" in script
    assert "after_sequence" in script
    assert "SSE did not reconnect from a persisted cursor" in script
    assert "data-conversation-stop" in script
    assert "data-cancel-dialog" in script
    assert "--start-only" in script
    assert "data-run-card].is-cancelled" in script
    assert "Show me the results" in script


def test_first_class_activity_entries_have_state_aware_presentation():
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(encoding="utf-8")
    script = (ROOT / "vulnhunter/web/static/web/conversation.js").read_text(encoding="utf-8")
    styles = (ROOT / "vulnhunter/web/static/web/conversation.css").read_text(encoding="utf-8")

    assert "data-activity-entry" in template
    assert "data-activity-marker" in template
    assert "data-activity-meta" in template
    assert "safeActivityState" in script
    assert "event.error_message" in script
    assert ".vh-chat-activity-entry.is-running" in styles
    assert ".vh-chat-activity-entry.is-failed" in styles


def test_conversation_runtime_uses_persisted_sse_and_keeps_composer_available():
    script = (ROOT / "vulnhunter/web/static/web/conversation.js").read_text(encoding="utf-8")

    assert "updateBusyCopy" in script
    assert "new EventSource" in script
    assert "mergeActivityPayload" in script
    assert "renderActivityEntries" in script
    assert "renderedActivity" in script
    assert "clearActivityEntries" in script
    assert "last_sequence" in script
    assert "closeActivityStream" in script
    assert "input.disabled = false" in script
    assert "announceRunProgress" not in script
    assert "contextualReply" not in script
    assert "confirmedRuns" in script


def test_background_upload_reconciles_timeout_after_server_success():
    script = (ROOT / "vulnhunter/web/static/web/conversation-upload-coordinator.js").read_text(
        encoding="utf-8"
    )

    assert "completeFromServerPayload" in script
    assert "if (await completeFromServerPayload(record, payload)) return true" in script
    assert "if (await reconcileOffset(record)) return" in script
    assert 'emit("vh:upload-complete", record)' in script
    assert "record.retryAt = 0" in script


def test_completed_apk_chat_uses_persisted_verification_and_report_truth():
    plan = {
        "execution": {
            "state": "completed",
            "receipt": {"captures": [], "candidate_observations": []},
            "progress": {
                "result_summary": {
                    "verification": {
                        "status": "abstained",
                        "verified_count": 0,
                        "rejected_count": 0,
                        "abstained_count": 0,
                    },
                    "report": {"status": "ready", "report_id": "report-one"},
                }
            },
        }
    }

    reply = mobile_chat_reply(
        text="What are the results?",
        intent="results",
        plan=plan,
        fallback=None,
    )

    assert "verification completed without generating a candidate vulnerability" in reply
    assert "report is ready" in reply
    assert "remain candidates" not in reply


def test_contextual_inspector_keeps_report_bound_to_selected_assessment():
    template = (ROOT / "vulnhunter/web/templates/web/_mobile_analysis_inspector.html").read_text(
        encoding="utf-8"
    )
    script = (ROOT / "vulnhunter/web/static/web/conversation-mobile-inspector.js").read_text(
        encoding="utf-8"
    )
    adapter = (ROOT / "vulnhunter/web/static/web/conversation-inspector-open.js").read_text(
        encoding="utf-8"
    )

    assert 'data-inspector-tab="reports"' in template
    assert 'data-inspector-panel="reports"' in template
    assert "Format readiness is unavailable until the server provides" in template
    assert "data-inspector-reports" in template
    assert 'reports: select("reports")' in script
    assert "const updateReports = () =>" in script
    assert "state.projection?.report" in script
    assert "selectedAssessmentId()" in script
    assert "updateReports();" in script
    assert 'event.target.closest?.("[data-analysis-inspector-open]")' in adapter
    assert "controller.click()" in adapter


def test_apk_task_uses_one_evolving_block_with_collapsed_technical_activity():
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(encoding="utf-8")
    script = (ROOT / "vulnhunter/web/static/web/conversation-mobile.js").read_text(encoding="utf-8")
    styles = (ROOT / "vulnhunter/web/static/web/conversation-mobile-execution.css").read_text(encoding="utf-8")

    assert 'data-mobile-live-stages' in template
    assert 'data-mobile-live-technical-events' in template
    assert 'Technical activity' in template
    assert 'data-mobile-live-stages' in script
    assert 'data-mobile-tool-id' in script
    assert 'mobileLiveStageEntries' in script
    assert 'data-mobile-live-steps' not in script
    assert '.vh-mobile-live-stage' in styles
    assert '.vh-mobile-live-technical' in styles
