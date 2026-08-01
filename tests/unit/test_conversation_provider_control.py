from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-provider-control.js"
RUNTIME = ROOT / "vulnhunter/web/static/web/conversation-runtime-compat.js"
STYLES = ROOT / "vulnhunter/web/static/web/workspace-final-fixes.css"
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


def test_provider_control_uses_only_self_hosted_static_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")
    upload_styles = UPLOAD_STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert ".style.setProperty" not in script
    assert ".style.removeProperty" not in script
    assert "ResizeObserver" not in script
    assert ".vh-provider-control" in styles
    assert ".vh-llm-progress" in styles
    assert ".vh-llm-progress-step.is-active" in styles
    assert "bottom: 10.5rem" in upload_styles
    assert "--vh-phone-composer-clearance" not in upload_styles