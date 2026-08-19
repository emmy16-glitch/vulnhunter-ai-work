"""Conversational planning helpers for the governed assessment workspace.

Remote AI may interpret and explain a request, but deterministic authorization and
assessment services remain authoritative. Raw private targets are never sent to
the
remote advisory provider. Conversational reasoning uses the configured high-capability
route with backend-owned provider failover; no provider switch grants authority and no
canned response is presented as model reasoning.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from django.conf import settings

from vulnhunter.providers import (
    GroqProvider,
    GroqProviderError,
    HuggingFaceProvider,
    HuggingFaceProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
)
from vulnhunter.security import redact_text

_URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_BRACKETED_IPV6_TARGET_PATTERN = re.compile(
    r"(?<![\w:])\[[0-9a-f:.%_-]+\](?::[0-9]{1,5})?(?:/[^\s<>'\"]*)?",
    re.IGNORECASE,
)
_BARE_TARGET_PATTERN = re.compile(
    r"(?<![\w.-])((?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:localhost|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+))"
    r":([0-9]{1,5})(?:/[^\s<>'\"]*)?",
    re.IGNORECASE,
)
_BARE_HOSTNAME_PATTERN = re.compile(
    r"(?<![@\w.-])(?:localhost|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?![\w.-])",
    re.IGNORECASE,
)
_PORT_PATTERN = re.compile(r"\bport\s*[:#-]?\s*([0-9]{1,5})\b", re.IGNORECASE)
_EVIDENCE_PATTERN = re.compile(r"\bevidence\s*[:=-]\s*(.+)$", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_COOKIE_ASSIGNMENT_PATTERN = re.compile(
    r"\b(cookie|set-cookie)\b(\s*[:=]\s*)[^\r\n]+",
    re.IGNORECASE,
)
_SECRET_TOKEN_PATTERN = re.compile(r"\b(?:sk|gsk)_[A-Za-z0-9_-]{10,}\b")
_PROFILE_WORDS = {
    "passive": "passive",
    "safe": "passive",
    "standard": "standard",
    "intrusive": "intrusive",
    "retest": "retest",
}
_CANCEL_WORDS = ("cancel", "stop", "abort")
_AUTHORIZE_WORDS = (
    "authorize",
    "authorise",
    "i own this target",
    "i control this target",
    "i am authorized",
    "i am authorised",
)
_APPROVE_WORDS = (
    "confirm",
    "approve",
    "confirm and continue",
    "go ahead",
    "start the assessment",
    "run it",
)
_RESULTS_WORDS = (
    "result",
    "results",
    "finding",
    "findings",
    "evidence",
    "vulnerability",
    "vulnerabilities",
    "what did you find",
    "show me",
)
_NEXT_STEP_WORDS = (
    "next step",
    "what next",
    "what should i do",
    "what do i do next",
    "next action",
)
_STATUS_WORDS = (
    "status",
    "progress",
    "what is happening",
    "what's happening",
    "what is it doing",
    "what's it doing",
    "how far",
    "has it started",
    "is it working",
    "is it running",
    "still pending",
    "approval pending",
    "how long",
    "is it done",
    "is it finished",
)
_REQUIRED_REASONING_EFFORT = "high"
_DEFAULT_REASONING_PROVIDER = "auto"
_HIGH_REASONING_UNAVAILABLE = (
    "I couldn't complete that response right now. Please retry in a moment. "
    "Deterministic authorization, status, scope, and execution controls remain available."
)


@dataclass(frozen=True)
class InterpretedRequest:
    intent: str
    target: str | None
    protocol: str | None
    port: int | None
    profile: str | None
    evidence_reference: str | None
    assistant_copy: str | None
    provider: str
    provider_detail: str
    model: str | None = None
    reasoning_effort: str = _REQUIRED_REASONING_EFFORT


def canonical_target(value: str) -> str:
    """Return a stable URL form for exact authorization matching."""

    candidate = value.strip().rstrip(".,;)")
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        if not hostname or parsed.username or parsed.password:
            return ""
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return ""
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return ""
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    normalized_hostname = hostname.lower()
    display_hostname = (
        f"[{normalized_hostname}]" if ":" in normalized_hostname else normalized_hostname
    )
    netloc = f"{display_hostname}:{port}"
    return urlunsplit((scheme, netloc, path, "", ""))


def extract_target(text: str) -> str | None:
    match = _URL_PATTERN.search(text)
    if match:
        return canonical_target(match.group(0)) or None
    match = _BRACKETED_IPV6_TARGET_PATTERN.search(text)
    if match:
        return canonical_target(match.group(0)) or None
    match = _BARE_TARGET_PATTERN.search(text)
    if match:
        return canonical_target(match.group(0)) or None
    match = _BARE_HOSTNAME_PATTERN.search(text)
    if match:
        return canonical_target(match.group(0)) or None
    return None


def extract_port(text: str, target: str | None) -> int | None:
    if target:
        try:
            parsed = urlsplit(target)
            return parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return None
    match = _PORT_PATTERN.search(text)
    if not match:
        return None
    value = int(match.group(1))
    return value if 1 <= value <= 65_535 else None


def extract_profile(text: str) -> str | None:
    lowered = text.casefold()
    for word, profile in _PROFILE_WORDS.items():
        if re.search(rf"\b{re.escape(word)}\b", lowered):
            return profile
    return None


def extract_evidence_reference(text: str) -> str | None:
    match = _EVIDENCE_PATTERN.search(text)
    if not match:
        return None
    value = redact_text(" ".join(match.group(1).split())).strip()[:2_000]
    if not value or value.startswith("<") or value.startswith("["):
        return None
    return value


def _contains_term(text: str, term: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(term)}(?!\w)", text) is not None


def deterministic_intent(text: str) -> str:
    """Classify high-impact actions locally and leave ordinary messages as chat."""

    lowered = " ".join(text.casefold().split())
    if any(_contains_term(lowered, word) for word in _AUTHORIZE_WORDS):
        return "authorize"
    if any(_contains_term(lowered, word) for word in _CANCEL_WORDS):
        return "cancel"
    if any(_contains_term(lowered, word) for word in _APPROVE_WORDS):
        return "approve"
    if any(_contains_term(lowered, word) for word in _STATUS_WORDS):
        return "status"
    if any(_contains_term(lowered, word) for word in _NEXT_STEP_WORDS):
        return "next_step"
    if any(_contains_term(lowered, word) for word in _RESULTS_WORDS):
        return "results"
    target = extract_target(text)
    if target:
        return "scan"
    asks_for_scan = any(_contains_term(lowered, word) for word in ("scan", "assess"))
    names_target = any(
        _contains_term(lowered, word)
        for word in ("website", "site", "domain", "host", "url", "target")
    )
    if asks_for_scan and names_target:
        return "scan"
    return "chat"


def _sanitize_for_groq(text: str) -> str:
    """Apply central redaction plus target-specific removal before remote inference."""

    sanitized = redact_text(text)
    sanitized = _COOKIE_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        sanitized,
    )
    sanitized = _URL_PATTERN.sub("[AUTHORIZED_TARGET]", sanitized)
    sanitized = _BRACKETED_IPV6_TARGET_PATTERN.sub("[AUTHORIZED_TARGET]", sanitized)
    sanitized = _BARE_TARGET_PATTERN.sub("[AUTHORIZED_TARGET]", sanitized)
    sanitized = _IPV4_PATTERN.sub("[PRIVATE_ADDRESS]", sanitized)
    sanitized = _BARE_HOSTNAME_PATTERN.sub("[PRIVATE_HOST]", sanitized)
    sanitized = _SECRET_TOKEN_PATTERN.sub("[REDACTED]", sanitized)
    return sanitized[:24_000]


def _reasoning_budget(_effort: str = _REQUIRED_REASONING_EFFORT) -> dict[str, int]:
    """Return the only supported conversational reasoning budget."""

    return {
        "input_bytes": 96_000,
        "input_tokens": 24_000,
        "output_tokens": 6_000,
        "output_bytes": 40_000,
        "timeout": 300,
    }


def _advisory_prompt(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...],
    memory_summary: str,
    tool_context: str,
    reasoning_effort: str,
) -> str:
    budget = _reasoning_budget(reasoning_effort)
    context_items = [
        {"role": role, "content": _sanitize_for_groq(content)[:2_000]}
        for role, content in conversation_context[-30:]
        if role in {"user", "assistant"} and content.strip()
    ]
    envelope = {
        "reasoning_effort": _REQUIRED_REASONING_EFFORT,
        "reasoning_policy": {
            "model_downgrade_allowed": False,
            "provider_fallback_allowed": False,
            "deterministic_chat_fallback_allowed": False,
        },
        "answer_expectation": (
            "Perform a deep internal analysis, compare plausible interpretations, check the "
            "available evidence, and give a thorough, non-repetitive answer with concrete next "
            "steps."
        ),
        "available_profiles": list(available_profiles),
        "durable_memory": _sanitize_for_groq(memory_summary)[:12_000],
        "recent_conversation": context_items,
        "read_only_workspace_tools": _sanitize_for_groq(tool_context)[:24_000],
        "user_request": _sanitize_for_groq(text)[:8_000],
        "output_limit_tokens": budget["output_tokens"],
    }
    return (
        "Act as VulnHunter's capable conversational security assistant. Answer ordinary questions "
        "directly rather than steering every message into a scan. You may answer broad lawful "
        "questions, teach concepts, analyse supplied evidence, explain APK and website results, "
        "and reason about the persisted workspace context. Avoid passive, canned, repetitive "
        "copy. Use the read-only workspace data when relevant and clearly distinguish stored "
        "evidence from inference. Never invent tool results. The deterministic backend alone "
        "authorizes targets, changes scope, approves or cancels actions, executes scanners, "
        "verifies findings, sets final severity, or publishes results. Do not reveal hidden "
        "chain-of-thought; provide conclusions and concise supporting rationale. The provider "
        "wrapper requires exactly one outer JSON object with output_kind and content. Set "
        "output_kind to CANDIDATE_ANALYSIS. Set content to a JSON-encoded string containing "
        "message and recommended_profile. message must contain the complete user-facing answer. "
        "recommended_profile must be one available profile or null. Do not return message and "
        "recommended_profile as the outer object. "
        + json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )


def _provider_invocation(
    *,
    provider: ProviderKind,
    model: str,
    prompt: str,
    reasoning_effort: str,
    timeout_cap: int,
) -> ProviderInvocation:
    budget = _reasoning_budget(reasoning_effort)
    raw = prompt.encode("utf-8")
    invocation_id = f"chat-{uuid4().hex[:20]}"
    return ProviderInvocation(
        invocation_id=invocation_id,
        request_id=invocation_id,
        provider=provider,
        model=model,
        capability=ProviderCapability.CONVERSATION,
        input_sha256=hashlib.sha256(raw).hexdigest(),
        maximum_input_characters=min(100_000, budget["input_bytes"]),
        maximum_output_characters=min(40_000, budget["output_bytes"]),
        maximum_input_bytes=min(100_000, budget["input_bytes"]),
        maximum_output_bytes=min(40_000, budget["output_bytes"]),
        maximum_input_tokens=min(25_000, budget["input_tokens"]),
        maximum_output_tokens=min(8_192, budget["output_tokens"]),
        timeout_seconds=min(300, budget["timeout"], timeout_cap),
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
    )


def _decode_advisory(response, available_profiles: tuple[str, ...]) -> str:
    try:
        payload = json.loads(response.content)
    except json.JSONDecodeError as exc:
        raise ValueError("The advisory provider returned unusable JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("The advisory provider returned an unusable response.")
    message = payload.get("message")
    recommendation = payload.get("recommended_profile")
    if not isinstance(message, str) or not message.strip():
        raise ValueError("The advisory provider omitted its answer.")
    result = {
        "message": redact_text(message.strip())[:40_000],
        "recommended_profile": (
            recommendation if recommendation in set(available_profiles) else None
        ),
        "model": response.model,
    }
    return json.dumps(result)


def _groq_advisory(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
    memory_summary: str = "",
    tool_context: str = "",
    reasoning_effort: str = _REQUIRED_REASONING_EFFORT,
) -> tuple[str | None, str]:
    if not getattr(settings, "VULNHUNTER_GROQ_ENABLED", False):
        return None, "Groq high-reasoning advisory is disabled."
    key_path = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser()
    if not key_path.is_file():
        return None, "Groq high-reasoning API key has not been configured."
    prompt = _advisory_prompt(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
    )
    model = settings.VULNHUNTER_GROQ_MODEL
    invocation = _provider_invocation(
        provider=ProviderKind.GROQ_ADVISORY,
        model=model,
        prompt=prompt,
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
        timeout_cap=settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS,
    )
    try:
        provider = GroqProvider.from_key_file(
            key_path,
            approved_models=(model,),
            api_base=settings.VULNHUNTER_GROQ_API_BASE,
        )
        response = provider.invoke(invocation, prompt)
    except GroqProviderError as exc:
        return None, f"Groq high-reasoning configuration was rejected safely: {exc}"
    if response.output_kind == ProviderOutputKind.ABSTAIN:
        return None, response.safe_error or "Groq high-reasoning model abstained safely."
    if response.model != model:
        return None, "Groq returned a different model than the configured high-reasoning model."
    try:
        result = _decode_advisory(response, available_profiles)
    except ValueError as exc:
        return None, str(exc)
    return result, f"Groq high-reasoning model: {response.model}"


def _huggingface_advisory(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
    memory_summary: str = "",
    tool_context: str = "",
    reasoning_effort: str = _REQUIRED_REASONING_EFFORT,
) -> tuple[str | None, str]:
    if not getattr(settings, "VULNHUNTER_HUGGINGFACE_ENABLED", False):
        return None, "Hugging Face high-reasoning advisory is disabled."
    token_path = Path(settings.VULNHUNTER_HUGGINGFACE_TOKEN_FILE).expanduser()
    if not token_path.is_file():
        return None, "Hugging Face high-reasoning token has not been configured."
    prompt = _advisory_prompt(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
    )
    model = settings.VULNHUNTER_HUGGINGFACE_MODEL
    invocation = _provider_invocation(
        provider=ProviderKind.HUGGINGFACE_ADVISORY,
        model=model,
        prompt=prompt,
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
        timeout_cap=settings.VULNHUNTER_HUGGINGFACE_TIMEOUT_SECONDS,
    )
    try:
        provider = HuggingFaceProvider.from_token_file(
            token_path,
            approved_models=(model,),
            api_base=settings.VULNHUNTER_HUGGINGFACE_API_BASE,
        )
        response = provider.invoke(invocation, prompt)
    except HuggingFaceProviderError as exc:
        return None, f"Hugging Face high-reasoning configuration was rejected safely: {exc}"
    if response.output_kind == ProviderOutputKind.ABSTAIN:
        return None, response.safe_error or "Hugging Face high-reasoning model abstained safely."
    if response.model != model:
        return None, (
            "Hugging Face returned a different model than the configured high-reasoning model."
        )
    try:
        result = _decode_advisory(response, available_profiles)
    except ValueError as exc:
        return None, str(exc)
    return result, f"Hugging Face high-reasoning model: {response.model}"


def _remote_advisory(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...],
    memory_summary: str,
    tool_context: str,
    reasoning_effort: str,
    provider_preference: str,
) -> tuple[str | None, str, str]:
    """Invoke the configured advisory route; the installed failover owner may retry safely."""

    provider_name = "huggingface" if provider_preference == "huggingface" else "groq"
    function = _huggingface_advisory if provider_name == "huggingface" else _groq_advisory
    advisory, detail = function(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
    )
    return advisory, detail, provider_name


def interpret_request(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
    memory_summary: str = "",
    tool_context: str = "",
    reasoning_effort: str = _REQUIRED_REASONING_EFFORT,
    provider_preference: str = _DEFAULT_REASONING_PROVIDER,
) -> InterpretedRequest:
    """Combine deterministic action routing with one high-reasoning AI provider.

    Deterministic code remains authoritative for intent/action routing. It does not
    replace failed conversational reasoning with a canned assistant answer.
    """

    del reasoning_effort
    provider_preference = (
        "huggingface" if provider_preference == "huggingface" else _DEFAULT_REASONING_PROVIDER
    )
    target = extract_target(text)
    port = extract_port(text, target)
    protocol = urlsplit(target).scheme if target else None
    profile = extract_profile(text)
    evidence_reference = extract_evidence_reference(text)
    intent = deterministic_intent(text)
    assistant_copy: str | None = None
    model: str | None = None

    advisory, advisory_detail, selected_provider = _remote_advisory(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
        provider_preference=provider_preference,
    )
    if advisory:
        try:
            payload = json.loads(advisory)
        except json.JSONDecodeError:
            payload = {}
        advisory_profile = payload.get("recommended_profile")
        if profile is None and advisory_profile in set(available_profiles):
            profile = advisory_profile
        copy = payload.get("message")
        if isinstance(copy, str) and copy.strip():
            assistant_copy = copy.strip()[:40_000]
        model_value = payload.get("model")
        model = model_value if isinstance(model_value, str) else None
    elif intent == "chat":
        assistant_copy = _HIGH_REASONING_UNAVAILABLE

    return InterpretedRequest(
        intent=intent,
        target=target,
        protocol=protocol,
        port=port,
        profile=profile,
        evidence_reference=evidence_reference,
        assistant_copy=assistant_copy,
        provider=selected_provider,
        provider_detail=advisory_detail,
        model=model,
        reasoning_effort=_REQUIRED_REASONING_EFFORT,
    )


def advisory_runtime_status() -> dict[str, object]:
    groq_enabled = bool(getattr(settings, "VULNHUNTER_GROQ_ENABLED", False))
    groq_key = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser()
    hf_enabled = bool(getattr(settings, "VULNHUNTER_HUGGINGFACE_ENABLED", False))
    hf_token = Path(settings.VULNHUNTER_HUGGINGFACE_TOKEN_FILE).expanduser()
    groq_configured = groq_enabled and groq_key.is_file()
    hf_configured = hf_enabled and hf_token.is_file()
    configured = groq_configured or hf_configured
    runtime_verified = os.environ.get("VULNHUNTER_GROQ_RUNTIME_VERIFIED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    providers = []
    if groq_configured:
        providers.append("Groq")
    if hf_configured:
        providers.append("Hugging Face")
    live_verified = bool(groq_configured and runtime_verified)
    if live_verified:
        label = "Groq high-reasoning conversation ready"
    elif groq_configured:
        label = "Groq high-reasoning model configured; restart to verify live conversation"
    elif providers:
        label = f"{' + '.join(providers)} high-reasoning provider configured"
    else:
        label = "High-reasoning AI provider setup required"
    return {
        "enabled": groq_enabled or hf_enabled,
        "configured": configured,
        "live_verified": live_verified,
        "label": label,
        "model": settings.VULNHUNTER_GROQ_MODEL
        if groq_configured
        else settings.VULNHUNTER_HUGGINGFACE_MODEL,
        "providers": providers,
        "reasoning_effort": _REQUIRED_REASONING_EFFORT,
        "model_fallback_allowed": False,
        "provider_fallback_allowed": False,
    }


def groq_runtime_status() -> dict[str, object]:
    """Compatibility alias for templates and existing tests."""

    return advisory_runtime_status()
