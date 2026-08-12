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


def test_provider_control_persists_and_submits_the_selected_provider() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'option value="auto"' in script
    assert 'option value="groq"' in script
    assert 'option value="huggingface"' in script
    assert "initial.reasoning_url" in script
    assert 'payload.set("provider_preference", nextValue)' in script
    assert 'options.body.set("provider_preference", state.preference)' in script
    assert "initial.thread_id" in script


def test_provider_progress_is_incremental_without_exposing_partial_model_json() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'progress.dataset.progressMode = "validated-stages"' in script
    assert "Preparing safe workspace context" in script
    assert "Waiting for a validated model response" in script
    assert "Checking and formatting the final answer" in script
    assert "data-llm-progress-elapsed" in script
    assert "stream: true" not in script
    assert "partial JSON" not in script


def test_actual_provider_and_model_are_taken_from_the_finished_message_badge() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'feed.querySelectorAll(".vh-message-reasoning")' in script
    assert 'state.lastProvider = "Hugging Face"' in script
    assert 'state.lastProvider = "Groq"' in script
    assert "state.lastModel" in script
    assert "AI unavailable · local fallback" in script


def test_provider_control_uses_only_self_hosted_live_static_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    composer_styles = COMPOSER_STYLES.read_text(encoding="utf-8")
    response_styles = RESPONSE_STYLES.read_text(encoding="utf-8")
    upload_styles = UPLOAD_STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert ".style.setProperty" not in script
    assert ".style.removeProperty" not in script
    assert "ResizeObserver" not in script
    assert ".vh-provider-control" in composer_styles
    assert ".vh-provider-control select" in composer_styles
    assert ".vh-llm-progress" in response_styles
    assert ".vh-llm-progress-step.is-active" in response_styles
    assert "background: var(--vh-pink)" in response_styles
    assert "border-radius: 999px" not in composer_styles + response_styles
    assert "rgba(108, 124, 255" not in composer_styles + response_styles
    assert "var(--vh-phone-composer-clearance" in upload_styles
    assert "env(safe-area-inset-bottom)" in upload_styles
    assert "100dvh" in upload_styles
