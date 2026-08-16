from __future__ import annotations

import stat
from io import StringIO

from django.core.management import call_command
from django.test import override_settings

from vulnhunter.web.management.commands import (
    vh_configure_groq,
    vh_configure_huggingface,
)


def _hidden_values(monkeypatch, module, *values: str) -> None:
    prompts = iter(values)
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: next(prompts))


@override_settings(
    VULNHUNTER_GROQ_ENABLED=True,
    VULNHUNTER_GROQ_API_KEY_FILE="/tmp/overridden-in-test",
)
def test_configure_groq_stores_owner_only_key_and_verifies_web_chat(monkeypatch, tmp_path) -> None:
    key_path = tmp_path / "groq.key"
    key = "gsk_test_key_abcdefghijklmnopqrstuvwxyz"
    _hidden_values(monkeypatch, vh_configure_groq, key, key)
    captured: dict[str, object] = {}

    def fake_call_command(name: str, **kwargs) -> None:
        captured["name"] = name
        captured.update(kwargs)

    monkeypatch.setattr(vh_configure_groq, "call_command", fake_call_command)
    monkeypatch.setattr(vh_configure_groq.settings, "VULNHUNTER_GROQ_API_KEY_FILE", str(key_path))
    stdout = StringIO()

    call_command("vh_configure_groq", key_file=str(key_path), stdout=stdout)

    assert key_path.read_text(encoding="utf-8") == f"{key}\n"
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert captured["name"] == "vh_verify_llm"
    assert captured["provider"] == "groq"
    assert captured["reasoning"] == "high"
    assert "Groq key stored securely" in stdout.getvalue()


@override_settings(
    VULNHUNTER_HUGGINGFACE_ENABLED=True,
    VULNHUNTER_HUGGINGFACE_TOKEN_FILE="/tmp/overridden-in-test",
)
def test_configure_huggingface_stores_owner_only_token_and_verifies_web_chat(
    monkeypatch, tmp_path
) -> None:
    token_path = tmp_path / "huggingface.token"
    token = "hf_test_token_abcdefghijklmnopqrstuvwxyz"
    _hidden_values(monkeypatch, vh_configure_huggingface, token, token)
    captured: dict[str, object] = {}

    def fake_call_command(name: str, **kwargs) -> None:
        captured["name"] = name
        captured.update(kwargs)

    monkeypatch.setattr(vh_configure_huggingface, "call_command", fake_call_command)
    monkeypatch.setattr(
        vh_configure_huggingface.settings,
        "VULNHUNTER_HUGGINGFACE_TOKEN_FILE",
        str(token_path),
    )
    stdout = StringIO()

    call_command("vh_configure_huggingface", token_file=str(token_path), stdout=stdout)

    assert token_path.read_text(encoding="utf-8") == f"{token}\n"
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
    assert captured["name"] == "vh_verify_llm"
    assert captured["provider"] == "huggingface"
    assert captured["reasoning"] == "low"
    assert "Hugging Face token stored securely" in stdout.getvalue()
