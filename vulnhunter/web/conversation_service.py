"""Conversational planning helpers for the governed assessment workspace.

Groq may interpret and explain a request, but deterministic authorization and
assessment services remain authoritative. Raw private targets are never sent to
the remote advisory provider.
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
    model: str | None = None
    reasoning_effort: str = "medium"


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


def _deterministic_chat_copy(
    text: str,
    *,
    conversation_context: tuple[tuple[str, str], ...] = (),
) -> str:
    """Answer common workspace questions while preserving recent local context."""

    lowered = " ".join(text.casefold().split())
    previous = [
        (role, " ".join(content.split()))
        for role, content in conversation_context[:-1]
        if role in {"user", "assistant"} and content.strip()
    ]
    prior_user = next((content for role, content in reversed(previous) if role == "user"), "")
    prior_assistant = next(
        (content for role, content in reversed(previous) if role == "assistant"),
        "",
    )

    if re.search(
        r"\b(what do you remember|remember what|what did i say|conversation context)\b", lowered
    ):
        if prior_user:
            return (
                "This workspace remembers the earlier messages and work attached to it. "
                f"Your previous request was about: {prior_user[:280]}"
            )
        return "This is a new workspace, so there is no earlier request to summarise yet."
    if re.search(r"\b(upload|uploading|apk upload|background)\b", lowered):
        return (
            "APK uploads are resumable in this workspace. You can open another page or another "
            "workspace; the upload dock keeps the transfer visible and resumes from the last "
            "server-confirmed byte after an interruption."
        )
    if re.search(r"\b(new chat|new workspace|multiple chats|recent chats|history)\b", lowered):
        return (
            "Each workspace now has separate persisted messages, uploads, selected APK plan and "
            "assessment state. Use New workspace for another task and History to reopen "
            "earlier work."
        )
    if re.search(r"\b(hello|hi|hey|good morning|good afternoon|good evening)\b", lowered):
        if prior_user:
            return (
                "Hello. I still have this workspace context. Your previous request was about "
                f"{prior_user[:220]}. You can continue from there or start a separate workspace."
            )
        return (
            "Hello. Start with an authorised website target or attach an APK. This workspace will "
            "preserve the conversation and any running work."
        )
    if any(term in lowered for term in ("what link", "which link", "what url", "target link")):
        return (
            "I can show the controlled target for the selected assessment. If this workspace "
            "has no "
            "assessment yet, send the exact authorised target you want checked."
        )
    if "approval" in lowered:
        return (
            "Approval applies only to the exact displayed passive plan. After confirmation, the "
            "scanner job continues on the server even when you leave this page."
        )
    if any(term in lowered for term in ("what can you do", "help me", "how do i use")):
        return (
            "I can keep separate website and APK investigations in persistent workspaces, prepare "
            "authorised bounded scans, explain live progress, and organise evidence-backed results."
        )
    if prior_user:
        candidate = (
            f"I am keeping the earlier context about {prior_user[:220]}. "
            "Ask a specific follow-up about its scope, upload, progress, evidence or next action, "
            "and I will answer from this workspace rather than restarting the conversation."
        )
    else:
        candidate = (
            "Describe the security question, paste an authorised http or https target, or "
            "attach an "
            "APK. I will keep the context in this workspace and separate it from your other tasks."
        )
    if prior_assistant and candidate == prior_assistant:
        return (
            "I have not lost the workspace context. Add the exact point you want examined "
            "next, and "
            "I will continue from the stored messages and current assessment state."
        )
    return candidate


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


def _reasoning_budget(effort: str) -> dict[str, int]:
    budgets = {
        "low": {
            "input_bytes": 24_000,
            "input_tokens": 6_000,
            "output_tokens": 900,
            "output_bytes": 12_000,
            "timeout": 60,
        },
        "medium": {
            "input_bytes": 60_000,
            "input_tokens": 15_000,
            "output_tokens": 2_800,
            "output_bytes": 28_000,
            "timeout": 150,
        },
        "high": {
            "input_bytes": 96_000,
            "input_tokens": 24_000,
            "output_tokens": 6_000,
            "output_bytes": 40_000,
            "timeout": 300,
        },
    }
    return budgets.get(effort, budgets["medium"])


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
        "reasoning_effort": reasoning_effort,
        "answer_expectation": {
            "low": "Answer directly and efficiently, but still solve the question.",
            "medium": (
                "Analyse the question carefully, connect relevant context, and explain a "
                "useful answer."
            ),
            "high": (
                "Perform a deep internal analysis, compare plausible interpretations, check the "
                "available evidence, and give a thorough, non-repetitive answer with "
                "concrete next steps."
            ),
        }[reasoning_effort],
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
        "questions, teach concepts, analyse supplied evidence, explain APK and website "
        "results, and "
        "reason about the persisted workspace context. Avoid passive, canned, repetitive copy. "
        "Use the read-only workspace data when relevant and clearly distinguish stored "
        "evidence from "
        "inference. Never invent tool results. The deterministic backend alone authorizes targets, "
        "changes scope, approves or cancels actions, executes scanners, verifies findings, "
        "sets final "
        "severity, or publishes results. Do not reveal hidden chain-of-thought; provide "
        "conclusions and concise supporting rationale. The provider wrapper requires exactly one "
        "outer JSON object with output_kind and content. Set output_kind to CANDIDATE_ANALYSIS. "
        "Set content to a JSON-encoded string containing message and recommended_profile. message "
        "must contain the complete user-facing answer. recommended_profile must be one available "
        "profile or null. Do not return message and recommended_profile as the outer object. "
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
        reasoning_effort=reasoning_effort,
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
    reasoning_effort: str = "medium",
) -> tuple[str | None, str]:
    if not getattr(settings, "VULNHUNTER_GROQ_ENABLED", False):
        return None, "Groq advisory is disabled."
    key_path = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser()
    if not key_path.is_file():
        return None, "Groq API key has not been configured."
    prompt = _advisory_prompt(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=reasoning_effort,
    )
    model = (
        settings.VULNHUNTER_GROQ_FALLBACK_MODEL
        if reasoning_effort == "low"
        else settings.VULNHUNTER_GROQ_MODEL
    )
    invocation = _provider_invocation(
        provider=ProviderKind.GROQ_ADVISORY,
        model=model,
        prompt=prompt,
        reasoning_effort=reasoning_effort,
        timeout_cap=settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS,
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
        response = provider.invoke(invocation, prompt)
    except GroqProviderError as exc:
        return None, f"Groq configuration was rejected safely: {exc}"
    if response.output_kind == ProviderOutputKind.ABSTAIN:
        return None, response.safe_error or "Groq abstained safely."
    try:
        result = _decode_advisory(response, available_profiles)
    except ValueError as exc:
        return None, str(exc)
    return result, f"Groq model: {response.model}"


def _huggingface_advisory(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
    memory_summary: str = "",
    tool_context: str = "",
    reasoning_effort: str = "medium",
) -> tuple[str | None, str]:
    if not getattr(settings, "VULNHUNTER_HUGGINGFACE_ENABLED", False):
        return None, "Hugging Face advisory is disabled."
    token_path = Path(settings.VULNHUNTER_HUGGINGFACE_TOKEN_FILE).expanduser()
    if not token_path.is_file():
        return None, "Hugging Face token has not been configured."
    prompt = _advisory_prompt(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=reasoning_effort,
    )
    model = (
        settings.VULNHUNTER_HUGGINGFACE_FALLBACK_MODEL
        if reasoning_effort == "low"
        else settings.VULNHUNTER_HUGGINGFACE_MODEL
    )
    invocation = _provider_invocation(
        provider=ProviderKind.HUGGINGFACE_ADVISORY,
        model=model,
        prompt=prompt,
        reasoning_effort=reasoning_effort,
        timeout_cap=settings.VULNHUNTER_HUGGINGFACE_TIMEOUT_SECONDS,
    )
    try:
        provider = HuggingFaceProvider.from_token_file(
            token_path,
            approved_models=(
                settings.VULNHUNTER_HUGGINGFACE_MODEL,
                settings.VULNHUNTER_HUGGINGFACE_FALLBACK_MODEL,
            ),
            api_base=settings.VULNHUNTER_HUGGINGFACE_API_BASE,
        )
        response = provider.invoke(invocation, prompt)
    except HuggingFaceProviderError as exc:
        return None, f"Hugging Face configuration was rejected safely: {exc}"
    if response.output_kind == ProviderOutputKind.ABSTAIN:
        return None, response.safe_error or "Hugging Face abstained safely."
    try:
        result = _decode_advisory(response, available_profiles)
    except ValueError as exc:
        return None, str(exc)
    return result, f"Hugging Face model: {response.model}"


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
    providers = (
        (
            ("huggingface", _huggingface_advisory),
            ("groq", _groq_advisory),
        )
        if provider_preference == "huggingface"
        else (
            ("groq", _groq_advisory),
            ("huggingface", _huggingface_advisory),
        )
    )
    if provider_preference in {"groq", "huggingface"}:
        providers = tuple(item for item in providers if item[0] == provider_preference)
    details: list[str] = []
    for provider_name, function in providers:
        advisory, detail = function(
            text,
            available_profiles=available_profiles,
            conversation_context=conversation_context,
            memory_summary=memory_summary,
            tool_context=tool_context,
            reasoning_effort=reasoning_effort,
        )
        details.append(detail)
        if advisory:
            return advisory, detail, provider_name
    return None, " ".join(details), "deterministic"


def interpret_request(
    text: str,
    *,
    available_profiles: tuple[str, ...],
    conversation_context: tuple[tuple[str, str], ...] = (),
    memory_summary: str = "",
    tool_context: str = "",
    reasoning_effort: str = "medium",
    provider_preference: str = "auto",
) -> InterpretedRequest:
    """Combine deterministic action routing with full bounded conversational reasoning."""

    if reasoning_effort not in {"low", "medium", "high"}:
        reasoning_effort = "medium"
    if provider_preference not in {"auto", "groq", "huggingface"}:
        provider_preference = "auto"
    target = extract_target(text)
    port = extract_port(text, target)
    protocol = urlsplit(target).scheme if target else None
    profile = extract_profile(text)
    evidence_reference = extract_evidence_reference(text)
    intent = deterministic_intent(text)
    assistant_copy = (
        _deterministic_chat_copy(text, conversation_context=conversation_context)
        if intent == "chat"
        else None
    )
    provider = "deterministic"
    detail = "Deterministic action routing is active."
    model: str | None = None

    advisory, advisory_detail, selected_provider = _remote_advisory(
        text,
        available_profiles=available_profiles,
        conversation_context=conversation_context,
        memory_summary=memory_summary,
        tool_context=tool_context,
        reasoning_effort=reasoning_effort,
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
        provider = selected_provider
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
        model=model,
        reasoning_effort=reasoning_effort,
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
        label = "Groq live conversation ready"
    elif groq_configured:
        label = "Groq configured; restart to verify live conversation"
    elif providers:
        label = f"{' + '.join(providers)} configured"
    else:
        label = "AI provider setup required"
    return {
        "enabled": groq_enabled or hf_enabled,
        "configured": configured,
        "live_verified": live_verified,
        "label": label,
        "model": settings.VULNHUNTER_GROQ_MODEL
        if groq_configured
        else settings.VULNHUNTER_HUGGINGFACE_MODEL,
        "providers": providers,
    }


def groq_runtime_status() -> dict[str, object]:
    """Compatibility alias for templates and existing tests."""

    return advisory_runtime_status()
