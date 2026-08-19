"""Silent conversational AI failover for the VulnHunter workspace.

The deterministic backend remains authoritative for authorization, scope, execution,
verification, severity, and publication. This module only keeps ordinary advisory
conversation available when a remote model is rate-limited or unavailable.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from vulnhunter.security import redact_text

logger = logging.getLogger(__name__)

_INSTALLED = False
_ALLOWED_OLLAMA_HOSTS = {"127.0.0.1", "localhost", "::1"}
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]+$")
_CIRCUIT_LOCK = threading.RLock()
_CIRCUIT_FAILURE_THRESHOLD = 2
_CIRCUIT_COOLDOWN_SECONDS = 15.0


@dataclass
class _ProviderCircuit:
    failures: int = 0
    state: str = "healthy"
    cooldown_until: float = 0.0


_CIRCUITS: dict[str, _ProviderCircuit] = {}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def _circuit(name: str) -> _ProviderCircuit:
    with _CIRCUIT_LOCK:
        return _CIRCUITS.setdefault(name, _ProviderCircuit())


def _provider_available(name: str, now: float | None = None) -> bool:
    instant = time.monotonic() if now is None else now
    with _CIRCUIT_LOCK:
        circuit = _circuit(name)
        if circuit.state == "cooldown" and instant < circuit.cooldown_until:
            return False
        if circuit.state == "cooldown":
            circuit.state = "probe"
        return True


def _provider_succeeded(name: str) -> None:
    with _CIRCUIT_LOCK:
        circuit = _circuit(name)
        circuit.failures = 0
        circuit.state = "healthy"
        circuit.cooldown_until = 0.0


def _provider_failed(name: str) -> None:
    with _CIRCUIT_LOCK:
        circuit = _circuit(name)
        circuit.failures += 1
        if circuit.failures >= _CIRCUIT_FAILURE_THRESHOLD:
            circuit.state = "cooldown"
            circuit.cooldown_until = time.monotonic() + _CIRCUIT_COOLDOWN_SECONDS
        else:
            circuit.state = "degraded"


def _provider_health_snapshot() -> dict[str, dict[str, object]]:
    now = time.monotonic()
    with _CIRCUIT_LOCK:
        snapshot: dict[str, dict[str, object]] = {}
        for name, circuit in _CIRCUITS.items():
            remaining = max(0.0, circuit.cooldown_until - now)
            snapshot[name] = {
                "state": "probe"
                if circuit.state == "cooldown" and remaining == 0
                else circuit.state,
                "failures": circuit.failures,
                "cooldown_seconds": round(remaining, 3),
            }
        return snapshot


def reset_provider_health() -> None:
    """Reset process-local health state for deterministic tests and controlled reloads."""
    with _CIRCUIT_LOCK:
        _CIRCUITS.clear()


def _failure_detail(detail: str) -> bool:
    lowered = detail.casefold()
    return any(
        marker in lowered
        for marker in (
            "timed out",
            "transport",
            "rate limit",
            "unavailable",
            "not reachable",
            "malformed",
            "rejected",
            "abstained",
            "disabled",
            "not configured",
        )
    )


def _read_secret(
    name: str,
    *,
    file_name: str,
    default_file: str,
) -> str | None:
    direct = os.environ.get(name, "").strip()
    if direct:
        return direct

    path = Path(os.environ.get(file_name, default_file)).expanduser()
    try:
        if not path.is_file() or path.is_symlink():
            return None
        metadata = path.stat()
        # API secrets should not be group/world readable or writable.
        if metadata.st_mode & 0o077:
            return None
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _strip_code_fence(value: str) -> str:
    text = value.strip()
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    if lines and lines[0].strip().casefold() in {"```", "```json"}:
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _normalise_answer(
    raw_text: str,
    *,
    available_profiles: tuple[str, ...],
    model: str,
) -> tuple[str | None, str]:
    """Convert Gemini/Ollama output into conversation_service's advisory envelope."""

    text = _strip_code_fence(raw_text)
    if not text:
        return None, "provider returned an empty response"

    payload: object
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # A useful plain-text answer is better than interrupting the conversation just
        # because the local model missed the requested JSON wrapper.
        message = redact_text(text).strip()[:40_000]
        if not message:
            return None, "provider returned unusable output"
        return (
            json.dumps(
                {
                    "message": message,
                    "recommended_profile": None,
                    "model": model,
                }
            ),
            "provider returned plain text and was normalised safely",
        )

    if not isinstance(payload, dict):
        return None, "provider returned an unusable JSON value"

    output_kind = str(payload.get("output_kind", "")).strip().upper()
    if output_kind == "ABSTAIN":
        safe_error = payload.get("safe_error")
        return None, str(safe_error or "provider abstained")[:500]

    candidate: object = payload
    if "content" in payload:
        candidate = payload.get("content")
        if isinstance(candidate, str):
            try:
                candidate = json.loads(candidate)
            except json.JSONDecodeError:
                candidate = {"message": candidate}

    if not isinstance(candidate, dict):
        return None, "provider omitted a usable answer"

    message = candidate.get("message")
    if not isinstance(message, str) or not message.strip():
        return None, "provider omitted its answer"

    recommendation = candidate.get("recommended_profile")
    result = {
        "message": redact_text(message.strip())[:40_000],
        "recommended_profile": (
            recommendation if recommendation in set(available_profiles) else None
        ),
        "model": model,
    }
    return json.dumps(result), "provider answer normalised"


def _fallback_prompt(conversation_service, *args, **kwargs) -> str:
    original = getattr(conversation_service, "_vulnhunter_original_advisory_prompt", None)
    if original is None:
        raise RuntimeError("The original advisory prompt is unavailable.")
    prompt = original(*args, **kwargs)
    return prompt.replace(
        '"provider_fallback_allowed":false',
        '"provider_fallback_allowed":true',
    )


def _build_prompt(
    conversation_service,
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...],
    memory_summary: str,
    tool_context: str,
    reasoning_effort: str,
) -> str:
    return conversation_service._advisory_prompt(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=reasoning_effort,
    )


def _gemini_advisory(
    conversation_service,
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
    memory_summary: str = "",
    tool_context: str = "",
    reasoning_effort: str = "high",
) -> tuple[str | None, str]:
    if not _env_bool("VULNHUNTER_GEMINI_ENABLED", False):
        return None, "Gemini advisory is disabled."

    api_key = _read_secret(
        "VULNHUNTER_GEMINI_API_KEY",
        file_name="VULNHUNTER_GEMINI_API_KEY_FILE",
        default_file=str(Path.home() / ".gemini-api-key"),
    )
    if not api_key:
        return None, "Gemini API key is not configured."

    api_base = os.environ.get(
        "VULNHUNTER_GEMINI_API_BASE",
        "https://generativelanguage.googleapis.com/v1beta",
    ).rstrip("/")
    parsed = urlsplit(api_base)
    if parsed.scheme != "https" or parsed.hostname != "generativelanguage.googleapis.com":
        return None, "Gemini API base was rejected by the outbound safety policy."

    model = os.environ.get("VULNHUNTER_GEMINI_MODEL", "gemini-3.6-flash").strip()
    if not _MODEL_PATTERN.fullmatch(model):
        return None, "Gemini model name is invalid."

    timeout = _env_int("VULNHUNTER_GEMINI_TIMEOUT_SECONDS", 75, minimum=5, maximum=180)
    prompt = _build_prompt(
        conversation_service,
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=reasoning_effort,
    )
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "maxOutputTokens": 6000,
            "thinkingConfig": {"thinkingLevel": "high"},
        },
    }

    try:
        response = httpx.post(
            f"{api_base}/models/{model}:generateContent",
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            json=body,
            timeout=timeout,
            follow_redirects=False,
        )
    except httpx.TimeoutException:
        return None, "Gemini request timed out."
    except httpx.HTTPError:
        return None, "Gemini transport failed."

    if response.status_code == 429:
        return None, "Gemini free-tier rate limit reached."
    if response.status_code in {408, 409, 425} or 500 <= response.status_code <= 599:
        return None, f"Gemini was temporarily unavailable ({response.status_code})."
    if response.status_code != 200:
        return None, f"Gemini rejected the request ({response.status_code})."

    try:
        payload = response.json()
        candidates = payload.get("candidates") or []
        parts = candidates[0]["content"]["parts"]
        raw_text = "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None, "Gemini returned a malformed response."

    return _normalise_answer(
        raw_text,
        available_profiles=available_profiles,
        model=model,
    )


def _ollama_advisory(
    conversation_service,
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
    memory_summary: str = "",
    tool_context: str = "",
    reasoning_effort: str = "high",
) -> tuple[str | None, str]:
    if not _env_bool("VULNHUNTER_OLLAMA_ENABLED", False):
        return None, "Ollama advisory is disabled."

    api_base = os.environ.get(
        "VULNHUNTER_OLLAMA_API_BASE",
        "http://127.0.0.1:11434",
    ).rstrip("/")
    parsed = urlsplit(api_base)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in _ALLOWED_OLLAMA_HOSTS:
        return None, "Ollama API base must resolve to loopback."

    model = os.environ.get("VULNHUNTER_OLLAMA_MODEL", "qwen3:1.7b").strip()
    if not _MODEL_PATTERN.fullmatch(model):
        return None, "Ollama model name is invalid."

    timeout = _env_int("VULNHUNTER_OLLAMA_TIMEOUT_SECONDS", 120, minimum=10, maximum=300)
    prompt = _build_prompt(
        conversation_service,
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=reasoning_effort,
    )
    thinking_control: bool | str = "high" if "gpt-oss" in model.casefold() else True
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Return JSON only and follow the response contract in the user prompt.",
            },
            {"role": "user", "content": prompt},
        ],
        "format": "json",
        "think": thinking_control,
        "stream": False,
    }

    try:
        response = httpx.post(
            f"{api_base}/api/chat",
            json=body,
            timeout=timeout,
            follow_redirects=False,
        )
    except httpx.TimeoutException:
        return None, "Ollama request timed out."
    except httpx.HTTPError:
        return None, "Ollama is not reachable."

    if response.status_code != 200:
        return None, f"Ollama was unavailable ({response.status_code})."

    try:
        payload = response.json()
        raw_text = str(payload["message"]["content"])
    except (ValueError, KeyError, TypeError):
        return None, "Ollama returned a malformed response."

    return _normalise_answer(
        raw_text,
        available_profiles=available_profiles,
        model=model,
    )


def _provider_status() -> dict[str, bool]:
    gemini_key = _read_secret(
        "VULNHUNTER_GEMINI_API_KEY",
        file_name="VULNHUNTER_GEMINI_API_KEY_FILE",
        default_file=str(Path.home() / ".gemini-api-key"),
    )
    return {
        "gemini": _env_bool("VULNHUNTER_GEMINI_ENABLED", False) and bool(gemini_key),
        "ollama": _env_bool("VULNHUNTER_OLLAMA_ENABLED", False),
    }


def install() -> None:
    """Install the failover router once Django has loaded the web application."""

    global _INSTALLED
    if _INSTALLED:
        return

    from vulnhunter.web import conversation_service as conversation_service

    if not hasattr(conversation_service, "_vulnhunter_original_advisory_prompt"):
        conversation_service._vulnhunter_original_advisory_prompt = (
            conversation_service._advisory_prompt
        )

    def advisory_prompt(*args, **kwargs):
        return _fallback_prompt(conversation_service, *args, **kwargs)

    def remote_advisory(
        text: str,
        *,
        available_profiles: tuple[str, ...],
        conversation_context: tuple[tuple[str, str], ...],
        memory_summary: str,
        tool_context: str,
        reasoning_effort: str,
        provider_preference: str,
    ) -> tuple[str | None, str, str]:
        # Keep the legacy parameter only for call-signature compatibility. Provider
        # selection is fully internal and always starts at the governed primary route.
        del provider_preference
        common = {
            "available_profiles": available_profiles,
            "conversation_context": conversation_context,
            "memory_summary": memory_summary,
            "tool_context": tool_context,
            "reasoning_effort": reasoning_effort,
        }

        providers: list[tuple[str, Callable[..., tuple[str | None, str]]]] = [
            ("groq", conversation_service._groq_advisory),
            (
                "gemini",
                lambda value, **kwargs: _gemini_advisory(conversation_service, value, **kwargs),
            ),
            (
                "ollama",
                lambda value, **kwargs: _ollama_advisory(conversation_service, value, **kwargs),
            ),
        ]

        attempted: list[str] = []
        for provider_name, provider in providers:
            if not _provider_available(provider_name):
                attempted.append(f"{provider_name}: circuit cooldown")
                continue
            try:
                advisory, detail = provider(text, **common)
            except Exception as exc:  # fail closed at the provider boundary
                logger.warning(
                    "AI provider %s failed unexpectedly: %s",
                    provider_name,
                    type(exc).__name__,
                )
                advisory, detail = None, "unexpected provider failure"
            attempted.append(f"{provider_name}: {detail}")
            if advisory:
                _provider_succeeded(provider_name)
                if len(attempted) > 1:
                    logger.info(
                        "Conversational AI failover succeeded with %s after %d attempts.",
                        provider_name,
                        len(attempted),
                    )
                # Keep provider switching out of user-facing copy/metadata details.
                return advisory, "AI reasoning completed.", "auto"
            if _failure_detail(detail):
                _provider_failed(provider_name)

        logger.warning(
            "All conversational AI providers were unavailable: %s",
            " | ".join(attempted),
        )
        return None, "AI reasoning is temporarily unavailable.", "auto"

    original_status = conversation_service.advisory_runtime_status

    def advisory_runtime_status() -> dict[str, object]:
        status = dict(original_status())
        extra = _provider_status()
        enabled = bool(status.get("enabled")) or any(extra.values())
        configured = bool(status.get("configured")) or any(extra.values())
        # This dictionary is consumed by the workspace template, so expose only
        # aggregate capability state. Provider/model inventory belongs in server logs.
        health = _provider_health_snapshot()
        degraded = any(
            item.get("state") in {"degraded", "cooldown", "probe"} for item in health.values()
        )
        return {
            "enabled": enabled,
            "configured": configured,
            "live_verified": bool(status.get("live_verified")),
            "label": (
                "AI reasoning temporarily degraded"
                if configured and degraded
                else "AI reasoning available"
                if configured
                else "AI reasoning unavailable"
            ),
            "reasoning_effort": "high",
            "model_fallback_allowed": False,
            "provider_fallback_allowed": True,
        }

    conversation_service._advisory_prompt = advisory_prompt
    conversation_service._remote_advisory = remote_advisory
    conversation_service._HIGH_REASONING_UNAVAILABLE = (
        "I couldn't complete that response right now. Please retry in a moment."
    )
    conversation_service.advisory_runtime_status = advisory_runtime_status
    conversation_service.groq_runtime_status = advisory_runtime_status
    _INSTALLED = True
