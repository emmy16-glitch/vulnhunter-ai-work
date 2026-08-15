from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vulnhunter.providers import ProviderOutputKind
from vulnhunter.web.conversation_service import (
    _groq_advisory,
    deterministic_intent,
    interpret_request,
)
from vulnhunter.web.mobile_conversation_state import mobile_chat_reply

ROOT = Path(__file__).resolve().parents[2]


def test_ordinary_question_reports_chat_unavailable_without_starting_scan(settings):
    settings.VULNHUNTER_GROQ_ENABLED = False

    result = interpret_request(
        "What link should I use?",
        available_profiles=("passive",),
    )

    assert result.intent == "chat"
    assert result.target is None
    assert result.provider == "groq"
    assert result.model is None
    assert result.reasoning_effort == "high"
    assert result.assistant_copy
    assert "AI conversation is temporarily unavailable" in result.assistant_copy
    assert "No security action was authorized or executed" in result.assistant_copy


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


def _configure_groq_chat_test(settings, tmp_path) -> None:
    key = tmp_path / "groq.key"
    key.write_text("gsk_test_value", encoding="utf-8")
    key.chmod(0o600)
    settings.VULNHUNTER_GROQ_ENABLED = True
    settings.VULNHUNTER_GROQ_API_KEY_FILE = str(key)
    settings.VULNHUNTER_GROQ_API_BASE = "https://api.groq.com/openai/v1"
    settings.VULNHUNTER_GROQ_MODEL = "openai/gpt-oss-120b"
    settings.VULNHUNTER_GROQ_FALLBACK_MODEL = "openai/gpt-oss-20b"
    settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS = 90


def test_ordinary_chat_uses_same_provider_fallback_after_primary_abstains(settings, tmp_path):
    _configure_groq_chat_test(settings, tmp_path)
    calls: list[tuple[str, int, int]] = []

    class FakeProvider:
        def invoke(self, invocation, prompt):
            del prompt
            calls.append(
                (
                    invocation.model,
                    invocation.maximum_input_tokens,
                    invocation.maximum_output_tokens,
                )
            )
            if len(calls) == 1:
                return SimpleNamespace(
                    output_kind=ProviderOutputKind.ABSTAIN,
                    safe_error="Groq request was rate-limited.",
                    model=invocation.model,
                    content="",
                )
            return SimpleNamespace(
                output_kind=ProviderOutputKind.CANDIDATE_ANALYSIS,
                safe_error=None,
                model=invocation.model,
                content=json.dumps(
                    {
                        "message": "Fallback answered normally.",
                        "recommended_profile": None,
                    }
                ),
            )

    with patch(
        "vulnhunter.web.conversation_service.GroqProvider.from_key_file",
        return_value=FakeProvider(),
    ):
        advisory, detail = _groq_advisory(
            "Can you explain APK analysis?",
            available_profiles=("passive",),
        )

    assert advisory is not None
    payload = json.loads(advisory)
    assert payload["message"] == "Fallback answered normally."
    assert payload["model"] == "openai/gpt-oss-20b"
    assert calls == [
        ("openai/gpt-oss-120b", 6_000, 1_200),
        ("openai/gpt-oss-20b", 6_000, 1_200),
    ]
    assert "resilient chat fallback" in detail


def test_scan_request_never_downgrades_to_chat_fallback_model(settings, tmp_path):
    _configure_groq_chat_test(settings, tmp_path)
    calls: list[tuple[str, int, int]] = []

    class AbstainingProvider:
        def invoke(self, invocation, prompt):
            del prompt
            calls.append(
                (
                    invocation.model,
                    invocation.maximum_input_tokens,
                    invocation.maximum_output_tokens,
                )
            )
            return SimpleNamespace(
                output_kind=ProviderOutputKind.ABSTAIN,
                safe_error="Groq request was rate-limited.",
                model=invocation.model,
                content="",
            )

    with patch(
        "vulnhunter.web.conversation_service.GroqProvider.from_key_file",
        return_value=AbstainingProvider(),
    ):
        advisory, _detail = _groq_advisory(
            "Scan this website",
            available_profiles=("passive",),
        )

    assert advisory is None
    assert deterministic_intent("Scan this website") == "scan"
    assert calls == [("openai/gpt-oss-120b", 24_000, 6_000)]


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


def test_conversation_ui_has_elapsed_thinking_and_contextual_answers():
    script = (ROOT / "vulnhunter/web/static/web/conversation.js").read_text(encoding="utf-8")

    assert "updateBusyCopy" in script
    assert "announceRunProgress" in script
    assert "next.final_message" in script
    assert "run.current_step" in script
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
