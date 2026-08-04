from pathlib import Path

TEMPLATE = Path("vulnhunter/web/templates/web/conversation.html")


def _template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def test_primary_composer_keeps_infrastructure_controls_behind_disclosure() -> None:
    template = _template()

    input_shell_start = template.index('<div class="vh-chat-input-shell">')
    input_shell_end = template.index("</div>", input_shell_start)
    input_shell = template[input_shell_start:input_shell_end]

    assert "data-reasoning-effort" not in input_shell
    assert "data-provider-runtime" not in input_shell
    assert '<details class="vh-composer-advanced" data-composer-advanced>' in template
    assert "<summary>Advanced settings</summary>" in template
    assert "data-reasoning-effort" in template
    assert "data-provider-runtime" in template


def test_composer_uses_ordinary_language_before_provider_language() -> None:
    template = _template()

    assert (
        'placeholder="Describe an authorised website, attach an APK, or ask about a finding"'
        in template
    )
    assert "Answer detail" in template
    assert ">Brief</option>" in template
    assert ">Balanced</option>" in template
    assert ">Detailed</option>" in template
    assert "Groq live" not in template
    assert "Groq unavailable" not in template
    assert "Advisory provider ready" in template
    assert "deterministic workflows remain available" in template


def test_composer_preserves_existing_submission_contracts() -> None:
    template = _template()

    assert 'name="reasoning_effort"' in template
    assert "data-reasoning-url" in template
    assert "data-conversation-send" in template
    assert "data-conversation-attach" in template
    assert 'accept=".apk,application/vnd.android.package-archive"' in template
