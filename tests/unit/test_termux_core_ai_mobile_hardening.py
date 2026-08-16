from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREVIEW = ROOT / "scripts/run_local_preview.py"
GROQ_CONFIG = ROOT / "vulnhunter/web/management/commands/vh_configure_groq.py"
DRAFT = ROOT / "vulnhunter/web/static/web/conversation-draft.js"
PROVIDER_CONTROL = ROOT / "vulnhunter/web/static/web/conversation-provider-control.js"
RESPONSE_STYLES = ROOT / "vulnhunter/web/static/web/conversation-response-controls.css"
RUNTIME = ROOT / "vulnhunter/web/static/web/conversation-runtime-compat.js"


def test_termux_preview_discovers_secure_core_ai_credentials() -> None:
    source = PREVIEW.read_text(encoding="utf-8")

    assert 'enabled_name="VULNHUNTER_GROQ_ENABLED"' in source
    assert 'key_file_name="VULNHUNTER_GROQ_API_KEY_FILE"' in source
    assert 'home / ".groq-api-key"' in source
    assert 'enabled_name="VULNHUNTER_GEMINI_ENABLED"' in source
    assert 'key_file_name="VULNHUNTER_GEMINI_API_KEY_FILE"' in source
    assert 'config_root / "gemini.key"' in source
    assert '"VULNHUNTER_OLLAMA_ENABLED"' in source
    assert 'enabled_name="VULNHUNTER_OLLAMA_ENABLED"' not in source


def test_termux_preview_respects_secret_file_and_existing_governance_store() -> None:
    source = PREVIEW.read_text(encoding="utf-8")

    assert 'has_secret_file = bool(os.environ.get("VULNHUNTER_WEB_SECRET_KEY_FILE"' in source
    assert "if not has_direct_secret and not has_secret_file:" in source
    assert 'local_governance = root / "governance.db"' in source
    assert "local_governance.is_file()" in source
    assert 'os.environ.setdefault("VULNHUNTER_GOVERNANCE_DATABASE"' in source


def test_groq_configuration_verifies_the_high_reasoning_path() -> None:
    source = GROQ_CONFIG.read_text(encoding="utf-8")

    assert 'provider="groq"' in source
    assert 'reasoning="high"' in source
    assert 'reasoning="low"' not in source


def test_submitted_prompt_is_separate_from_unsent_draft_across_reload() -> None:
    source = DRAFT.read_text(encoding="utf-8")

    pending_guard = (
        "if (!state.pendingPrompt && !pendingStorage.read()?.value) saveDraft({ quiet: true });"
    )
    pending_notice = (
        "Previous request was already submitted. Check the conversation before retrying."
    )

    assert "vulnhunter:conversation-pending:" in source
    assert "pendingStorage.write(value)" in source
    assert "storage.clear()" in source
    assert "state.pageLeaving = true" in source
    assert pending_guard in source
    assert pending_notice in source
    assert "restorePending" in source


def test_only_validated_progress_is_visible_during_ai_work() -> None:
    provider = PROVIDER_CONTROL.read_text(encoding="utf-8")
    styles = RESPONSE_STYLES.read_text(encoding="utf-8")

    assert 'thinking.classList.add("is-progress-delegated")' in provider
    assert 'thinking.setAttribute("aria-hidden", "true")' in provider
    assert ".vh-chat-thinking.is-progress-delegated" in styles
    assert "display: none !important" in styles
    assert 'progress.dataset.progressMode = "validated-stages"' in provider


def test_mobile_progress_and_secondary_composer_controls_stay_compact() -> None:
    styles = RESPONSE_STYLES.read_text(encoding="utf-8")

    assert "grid-template-columns: minmax(0, 1fr) auto auto" in styles
    assert ".vh-llm-progress-track" in styles
    assert "min-height: 32px" in styles
    assert ".vh-chat-composer-meta > span:not(.vh-draft-status)" in styles
    assert ".vh-composer-counter" in styles
    assert "@media (max-width: 640px)" in styles


def test_hardened_chat_assets_get_a_new_cache_version() -> None:
    runtime = RUNTIME.read_text(encoding="utf-8")

    assert 'version = "20260816-termux-hardening1"' in runtime
