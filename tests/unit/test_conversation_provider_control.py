from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-provider-control.js"
RUNTIME = ROOT / "vulnhunter/web/static/web/conversation-runtime-compat.js"
COMPOSER_STYLES = ROOT / "vulnhunter/web/static/web/conversation-composer-tools.css"
RESPONSE_STYLES = ROOT / "vulnhunter/web/static/web/conversation-response-controls.css"
UPLOAD_STYLES = ROOT / "vulnhunter/web/static/web/background-uploads.css"


def test_provider_control_is_loaded_by_the_existing_workspace_runtime() -> None:
    runtime = RUNTIME.read_text(encoding="utf-8")

    assert 'loadScript("conversation-provider-control.js"' in runtime
    assert "data-provider-control-loader" in runtime


def test_provider_routing_is_automatic_and_hidden_from_the_user() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'options.body.set("provider_preference", "auto")' in script
    assert 'runtime.dataset.providerPreferenceActive = "auto"' in script
    assert 'runtime.textContent = "Automatic routing"' in script
    assert "runtime.hidden = true" in script
    assert 'runtime.setAttribute("aria-hidden", "true")' in script
    assert 'runtime.classList.remove("is-ready", "is-warning", "is-offline")' in script
    assert 'querySelectorAll(".vh-provider-control")' in script
    assert "initial.thread_id" in script
    assert 'option value="groq"' not in script
    assert 'option value="huggingface"' not in script
    assert "select[data-provider-preference]" not in script
    assert '"AI reasoning ready"' not in script


def test_provider_progress_tracks_request_waiting_without_fake_validation_stages() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'progress.dataset.progressMode = "validated-stages"' in script
    assert 'progress.dataset.progressSource = "request-state"' in script
    assert "Reasoning over the request" in script
    assert "Still working through the request" in script
    assert "data-llm-progress-elapsed" in script
    assert "Validating the response" not in script
    assert "Formatting the final answer" not in script
    assert "currentStage" not in script
    assert "progressSteps" not in script
    assert "stream: true" not in script
    assert "partial JSON" not in script
    assert "Contacting Groq" not in script
    assert "Contacting Hugging Face" not in script
    assert "Contacting Gemini" not in script
    assert "Contacting Ollama" not in script


def test_finished_message_does_not_expose_provider_or_model_identity() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'runtime.textContent = "Automatic routing"' in script
    assert "runtime.hidden = true" in script
    assert 'feed.querySelectorAll(".vh-message-reasoning")' not in script
    assert "state.lastProvider" not in script
    assert "state.lastModel" not in script
    assert "AI unavailable · local fallback" not in script
    assert "observe(thinkingCopy" not in script


def test_provider_control_uses_only_self_hosted_live_static_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    composer_styles = COMPOSER_STYLES.read_text(encoding="utf-8")
    response_styles = RESPONSE_STYLES.read_text(encoding="utf-8")
    upload_styles = UPLOAD_STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert ".style.setProperty" not in script
    assert ".style.removeProperty" not in script
    assert "ResizeObserver" not in script
    assert ".vh-llm-progress" in response_styles
    assert "background: var(--vh-pink)" in response_styles
    assert "border-radius: 999px" not in composer_styles + response_styles
    assert "rgba(108, 124, 255" not in composer_styles + response_styles
    assert "var(--vh-phone-composer-clearance" in upload_styles
    assert "env(safe-area-inset-bottom)" in upload_styles
    assert "100dvh" in upload_styles
