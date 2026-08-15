from pathlib import Path

TEMPLATE = Path("vulnhunter/web/templates/web/conversation.html")
PROVIDER_CLIENT = Path("vulnhunter/web/static/web/conversation-provider-control.js")


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
    assert "<summary>Advanced</summary>" in template
    assert "data-reasoning-effort" in template
    assert "data-provider-runtime" in template


def test_provider_preference_control_stays_inside_advanced_container() -> None:
    client = PROVIDER_CLIENT.read_text(encoding="utf-8")

    assert "const providerContainer = runtime.parentElement;" in client
    assert "providerContainer.insertBefore(control, runtime);" in client
    assert "composerMeta.insertBefore(control, runtime);" not in client


def test_composer_exposes_only_the_enforced_high_reasoning_mode() -> None:
    template = _template()

    assert (
        'placeholder="Ask VulnHunter about an authorised target, APK, finding or evidence…"'
        in template
    )
    assert "Reasoning mode" in template
    assert ">High</option>" in template
    assert ">Brief</option>" not in template
    assert ">Balanced</option>" not in template
    assert ">Detailed</option>" not in template
    assert "data-reasoning-copy>High</b> reasoning enforced" in template
    assert "Groq unavailable" not in template
    assert "High-reasoning provider ready" in template
    assert "deterministic workflows remain available" in template


def test_composer_preserves_existing_submission_contracts() -> None:
    template = _template()

    assert 'name="reasoning_effort"' in template
    assert "data-reasoning-url" in template
    assert "data-conversation-send" in template
    assert "data-conversation-attach" in template
    assert 'accept=".apk,application/vnd.android.package-archive"' in template
