from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"


def test_empty_conversation_has_no_synthetic_assistant_message():
    from vulnhunter.web import chat_experience, conversational_views

    chat_experience.install()
    request = SimpleNamespace(session={})

    assert conversational_views._messages(request) == []
    assert "vulnhunter_conversation_messages" not in request.session


def test_chat_metadata_strips_provider_infrastructure_details():
    from vulnhunter.web import chat_experience

    cleaned = chat_experience._public_metadata(
        {
            "provider": "groq",
            "model": "internal-model",
            "provider_detail": "internal runtime detail",
            "reasoning_effort": "high",
            "run_id": "run-123456",
        }
    )

    assert cleaned == {"reasoning_effort": "high", "run_id": "run-123456"}


def test_explicit_assessment_run_references_are_authoritatively_bound():
    from vulnhunter.web import chat_experience

    assert chat_experience._RUN_REFERENCE.search(
        "Show me findings for assessment run run-abcdef123"
    )
    source = (ROOT / "vulnhunter/web/chat_experience.py").read_text(encoding="utf-8")
    assert '"runs.view"' in source
    assert "_visible_run(run_id, actor)" in source
    assert "_sync_state_from_run" in source
    assert "not available to this account" in source


def test_command_center_keeps_operational_actions_in_chat():
    script = (STATIC / "conversation-command-center.js").read_text(encoding="utf-8")

    assert "data-run-cancel" in script
    assert "stopImmediatePropagation" in script
    assert "Show me the findings for the current assessment" in script
    assert "Show me all findings in this workspace" not in script
    assert "assessment run ${runId}" in script
    assert "Open Source Hunt in this conversation" in script
    assert "Open Active Validation for the current assessment in this conversation" in script
    assert "Open the final remediation report in this conversation" in script
    assert "Review remediation independently in this conversation" in script
    assert "governed retest status and verification result" in script
    assert "remediation status and the next governed step" in script
    assert "High reasoning · governed context" in script
    assert ".vh-new-assessment" in script
    assert "data-conversation-reset" in script
    assert "Start a clean assessment thread?" in script
    assert "commandCenterConfirmed" in script
    assert "Asking Groq" not in script
    assert "Gemini" not in script
    assert "Ollama" not in script


def test_provider_control_is_automatic_and_provider_names_stay_hidden():
    script = (STATIC / "conversation-provider-control.js").read_text(encoding="utf-8")

    assert 'options.body.set("provider_preference", "auto")' in script
    assert 'runtime.textContent = "Automatic routing"' in script
    assert "runtime.hidden = true" in script
    assert 'runtime.setAttribute("aria-hidden", "true")' in script
    assert 'runtime.classList.remove("is-ready", "is-warning", "is-offline")' in script
    assert "Reasoning over the request…" in script
    assert "Validating the response…" in script
    assert "Formatting the final answer…" in script
    assert 'querySelectorAll(".vh-provider-control")' in script
    assert "select[data-provider-preference]" not in script
    assert '"AI reasoning ready"' not in script
    assert "Contacting Groq" not in script
    assert "Contacting Hugging Face" not in script
    assert "Contacting Gemini" not in script
    assert "Contacting Ollama" not in script
    assert "observe(thinkingCopy" not in script


def test_specialist_bridge_does_not_reload_redirect_alert_or_expose_runtime():
    compat = (STATIC / "conversation-runtime-compat.js").read_text(encoding="utf-8")

    assert "vulnhunter:specialist-start" in compat
    assert "vulnhunter:specialist-response" in compat
    assert "vulnhunter:specialist-error" in compat
    assert "setSpecialistThinking(true, label)" in compat
    assert "setSpecialistThinking(false)" in compat
    assert "[data-conversation-thinking]" in compat
    assert "preloadCommandCenterStyles();" in compat
    assert 'runtime.textContent = "Automatic routing"' in compat
    assert "runtime.hidden = true" in compat
    assert '"AI reasoning ready"' not in compat
    assert "window.location.reload" not in compat
    assert "window.location.assign(body.redirect_url)" not in compat
    assert "window.alert" not in compat


def test_command_center_keeps_secret_reauthentication_out_of_chat_text():
    script = (STATIC / "conversation-command-center.js").read_text(encoding="utf-8")

    protected_copy = (
        "Password re-authentication and provider-processing consent must never be put in chat text"
    )
    assert protected_copy in script
    assert "Continue protected step" in script
    assert "window.location.assign(redirectUrl)" in script


def test_command_center_visuals_reuse_product_tokens_and_hide_runtime_before_paint():
    styles = (STATIC / "conversation-command-center.css").read_text(encoding="utf-8")

    for token in ("--vh-surface", "--vh-ink", "--vh-pink", "--vh-line"):
        assert token in styles
    assert "[data-provider-runtime]" in styles
    assert "display: none !important" in styles
    assert "prefers-reduced-motion" in styles
    assert "[data-cancel-dialog] { display: none !important; }" in styles
