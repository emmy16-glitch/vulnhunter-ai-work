"""Conversational planning helpers for the governed assessment workspace.

Groq may interpret and explain a request, but deterministic authorization and
assessment services remain authoritative. Raw private targets are never sent to
the remote advisory provider.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from django.conf import settings

from vulnhunter.providers import (
    GroqProvider,
    GroqProviderError,
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
_SCAN_WORDS = ("scan", "assess", "check", "inspect", "test", "analyse", "analyze")
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
    if any(_contains_term(lowered, word) for word in _SCAN_WORDS) or extract_target(text):
        return "scan"
    return "chat"


def _deterministic_chat_copy(text: str) -> str:
    lowered = " ".join(text.casefold().split())
    if re.search(r"\b(hello|hi|hey|good morning|good afternoon|good evening)\b", lowered):
        return (
            "Hello. I can answer questions about the active assessment, show its target and "
            "status, explain approval, or prepare a new authorised scan."
        )
    if any(term in lowered for term in ("what link", "which link", "what url", "target link")):
        return (
            "I can show the controlled target for the active assessment. If no assessment is "
            "active, send the authorised target you want checked."
        )
    if "approval" in lowered:
        return (
            "Approval applies only to the exact displayed passive plan. After confirmation, the "
            "approval card should disappear and live scanner progress should continue here."
        )
    if any(term in lowered for term in ("what can you do", "help me", "how do i use")):
        return (
            "Describe an authorised target or ask about the current run. I can prepare the bounded "
            "plan, explain each step, show progress and organise evidence-backed results."
        )
    return (
        "Paste an http or https website link and I will identify its host, path and port, check "
        "authorization, prepare the passive plan and explain each live step. You can also ask "
        "about the current target, approval, findings, evidence or next action."
    )


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
    return sanitized[:4_000]


def _groq_advisory(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
) -> tuple[str | None, str]:
    if not getattr(settings, "VULNHUNTER_GROQ_ENABLED", False):
        return None, "Groq advisory is disabled."
    key_path = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser()
    if not key_path.is_file():
        return None, "Groq API key has not been configured."

    sanitized = _sanitize_for_groq(text)
    sanitized_context = [
        {"role": role, "content": _sanitize_for_groq(content)[:600]}
        for role, content in conversation_context[-8:]
        if role in {"user", "assistant"} and content.strip()
    ]
    prompt = (
        "Act as the conversational layer for a governed cybersecurity assessment workspace. "
        "The deterministic backend alone owns authorization, target matching, cancellation, "
        "ports, approval, Nuclei execution, evidence and findings. Never claim that a tool ran, "
        "never invent a target, and never approve or cancel work. Respond naturally to ordinary "
        "questions instead of forcing every message into a scan flow. Return one JSON object with "
        "keys intent, message, recommended_profile, and missing. intent must be scan, status, or "
        "chat. Deterministic commands such as approve, cancel, results and next step are handled "
        "locally and cannot be changed by the provider. Use scan only when the user is asking to "
        "assess a target, status only for progress questions, and chat for greetings, "
        "explanations, help, links, or other ordinary conversation. "
        "recommended_profile must be one supplied profile or null. missing must be "
        "an array containing only target, port, profile, or authorization. Keep message helpful, "
        "specific and under 600 characters. Do not expose hidden reasoning. "
        f"Available profiles: {', '.join(available_profiles) or 'none'}. "
        f"Recent sanitized conversation: {json.dumps(sanitized_context, ensure_ascii=False)}. "
        f"Sanitized user request: {sanitized}"
    )
    raw = prompt.encode("utf-8")
    invocation_id = f"chat-{uuid4().hex[:20]}"
    invocation = ProviderInvocation(
        invocation_id=invocation_id,
        request_id=invocation_id,
        provider=ProviderKind.GROQ_ADVISORY,
        model=settings.VULNHUNTER_GROQ_MODEL,
        capability=ProviderCapability.CLASSIFICATION,
        input_sha256=hashlib.sha256(raw).hexdigest(),
        maximum_input_characters=8_000,
        maximum_output_characters=3_000,
        maximum_input_bytes=min(settings.VULNHUNTER_GROQ_MAX_INPUT_BYTES, 16_000),
        maximum_output_bytes=6_000,
        maximum_input_tokens=2_000,
        maximum_output_tokens=min(settings.VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS, 800),
        timeout_seconds=min(settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS, 60),
    )
    try:
        provider = GroqProvider.from_key_file(
            key_path,
            approved_models=(
                settings.VULNHUNTER_GROQ_MODEL,
                settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
            ),
            api_base=settings.VULNHUNTER_GROQ_API_BASE,
        )
        health = provider.health()
        if health.reachable and health.model and health.model != invocation.model:
            invocation = invocation.model_copy(update={"model": health.model})
        response = provider.invoke(invocation, prompt)
    except GroqProviderError as exc:
        return None, f"Groq configuration was rejected safely: {exc}"
    if response.output_kind == ProviderOutputKind.ABSTAIN:
        return None, response.safe_error or "Groq abstained safely."
    try:
        payload = json.loads(response.content)
    except json.JSONDecodeError:
        return None, "Groq returned an unusable advisory response."
    if not isinstance(payload, dict):
        return None, "Groq returned an unusable advisory response."
    message = payload.get("message")
    recommendation = payload.get("recommended_profile")
    result = {
        "intent": payload.get("intent"),
        "message": message if isinstance(message, str) else None,
        "recommended_profile": (
            recommendation if recommendation in set(available_profiles) else None
        ),
    }
    return json.dumps(result), f"Groq advisory model: {response.model}"


def interpret_request(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
) -> InterpretedRequest:
    """Combine deterministic extraction with a bounded Groq advisory."""

    target = extract_target(text)
    port = extract_port(text, target)
    protocol = urlsplit(target).scheme if target else None
    profile = extract_profile(text)
    evidence_reference = extract_evidence_reference(text)
    deterministic = deterministic_intent(text)
    intent = deterministic
    if deterministic == "chat":
        assistant_copy = _deterministic_chat_copy(text)
    elif deterministic == "status":
        assistant_copy = (
            "No assessment is active yet. Send an authorised target to start one, or ask what "
            "VulnHunter can do."
        )
    else:
        assistant_copy = None
    provider = "deterministic"
    detail = "Deterministic request parsing is active."

    advisory, advisory_detail = _groq_advisory(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
    )
    if advisory:
        try:
            payload = json.loads(advisory)
        except json.JSONDecodeError:
            payload = {}
        if deterministic == "scan":
            intent = "scan"
        advisory_profile = payload.get("recommended_profile")
        if profile is None and advisory_profile in set(available_profiles):
            profile = advisory_profile
        copy = payload.get("message")
        if isinstance(copy, str) and copy.strip():
            assistant_copy = redact_text(" ".join(copy.split()))[:600]
        provider = "groq"
        detail = advisory_detail
    else:
        detail = advisory_detail

    return InterpretedRequest(
        intent=intent,
        target=target,
        protocol=protocol,
        port=port,
        profile=profile,
        evidence_reference=evidence_reference,
        assistant_copy=assistant_copy,
        provider=provider,
        provider_detail=detail,
    )


def groq_runtime_status() -> dict[str, object]:
    enabled = bool(getattr(settings, "VULNHUNTER_GROQ_ENABLED", False))
    key_path = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser()
    configured = enabled and key_path.is_file()
    return {
        "enabled": enabled,
        "configured": configured,
        "label": "Groq ready" if configured else "Groq setup required",
        "model": settings.VULNHUNTER_GROQ_MODEL,
    }
