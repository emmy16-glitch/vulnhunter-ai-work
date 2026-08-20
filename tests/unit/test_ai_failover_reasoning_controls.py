from __future__ import annotations

import json
from types import SimpleNamespace

from vulnhunter.web import ai_failover


class _Response:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _conversation_service():
    return SimpleNamespace(_advisory_prompt=lambda *_args, **_kwargs: '{"reasoning_effort":"high"}')


def test_gemini_forces_high_thinking_level_and_fast_connect_timeout(monkeypatch):
    captured = {}
    monkeypatch.setenv("VULNHUNTER_GEMINI_ENABLED", "true")
    monkeypatch.setenv("VULNHUNTER_GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("VULNHUNTER_GEMINI_MODEL", "gemini-3.6-flash")
    monkeypatch.setenv("VULNHUNTER_GEMINI_TIMEOUT_SECONDS", "81")
    monkeypatch.setenv("VULNHUNTER_GEMINI_CONNECT_TIMEOUT_SECONDS", "3")

    def fake_post(*_args, **kwargs):
        captured.update(kwargs)
        return _Response(
            {"candidates": [{"content": {"parts": [{"text": json.dumps({"message": "ok"})}]}}]}
        )

    monkeypatch.setattr(ai_failover.httpx, "post", fake_post)

    advisory, _detail = ai_failover._gemini_advisory(
        _conversation_service(),
        "analyse this",
        available_profiles=("passive",),
        reasoning_effort="high",
    )

    assert advisory is not None
    generation_config = captured["json"]["generationConfig"]
    assert generation_config["thinkingConfig"]["thinkingLevel"] == "high"
    timeout = captured["timeout"]
    assert timeout.connect == 3.0
    assert timeout.read == 81.0
    assert timeout.write == 3.0
    assert timeout.pool == 3.0


def test_ollama_qwen3_explicitly_enables_thinking_and_fast_connect_timeout(monkeypatch):
    captured = {}
    monkeypatch.setenv("VULNHUNTER_OLLAMA_ENABLED", "true")
    monkeypatch.setenv("VULNHUNTER_OLLAMA_MODEL", "qwen3:1.7b")
    monkeypatch.setenv("VULNHUNTER_OLLAMA_TIMEOUT_SECONDS", "130")
    monkeypatch.setenv("VULNHUNTER_OLLAMA_CONNECT_TIMEOUT_SECONDS", "2")

    def fake_post(*_args, **kwargs):
        captured.update(kwargs)
        return _Response({"message": {"content": json.dumps({"message": "ok"})}})

    monkeypatch.setattr(ai_failover.httpx, "post", fake_post)

    advisory, _detail = ai_failover._ollama_advisory(
        _conversation_service(),
        "analyse this",
        available_profiles=("passive",),
        reasoning_effort="high",
    )

    assert advisory is not None
    assert captured["json"]["think"] is True
    timeout = captured["timeout"]
    assert timeout.connect == 2.0
    assert timeout.read == 130.0
    assert timeout.write == 2.0
    assert timeout.pool == 2.0


def test_ollama_gpt_oss_uses_high_reasoning_level(monkeypatch):
    captured = {}
    monkeypatch.setenv("VULNHUNTER_OLLAMA_ENABLED", "true")
    monkeypatch.setenv("VULNHUNTER_OLLAMA_MODEL", "gpt-oss:20b")

    def fake_post(*_args, **kwargs):
        captured.update(kwargs)
        return _Response({"message": {"content": json.dumps({"message": "ok"})}})

    monkeypatch.setattr(ai_failover.httpx, "post", fake_post)

    advisory, _detail = ai_failover._ollama_advisory(
        _conversation_service(),
        "analyse this",
        available_profiles=("passive",),
        reasoning_effort="high",
    )

    assert advisory is not None
    assert captured["json"]["think"] == "high"
