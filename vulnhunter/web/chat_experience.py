"""Strict chat-first workspace experience hooks.

This module intentionally changes presentation/session behaviour only. Deterministic
security authorization, approval binding, scanner execution and evidence handling stay
inside their existing services.
"""

from __future__ import annotations

_INSTALLED = False
_PRIVATE_MESSAGE_METADATA = frozenset({"provider", "model", "provider_detail"})


def _public_metadata(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): item
        for key, item in value.items()
        if str(key) not in _PRIVATE_MESSAGE_METADATA
    }


def _public_message(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    message = dict(value)
    message["metadata"] = _public_metadata(message.get("metadata"))
    return message


def install() -> None:
    """Keep empty threads clean and strip infrastructure details from chat messages."""

    global _INSTALLED
    if _INSTALLED:
        return

    from vulnhunter.web import conversational_views

    original_append_message = conversational_views._append_message

    def clean_messages(request):
        raw = request.session.get(conversational_views._SESSION_MESSAGES, [])
        if not isinstance(raw, list):
            raw = []
        bounded = raw[-conversational_views._MAX_MESSAGES :]
        cleaned = [
            message
            for item in bounded
            if (message := _public_message(item)) is not None
        ]
        if cleaned != bounded:
            request.session[conversational_views._SESSION_MESSAGES] = cleaned
            request.session.modified = True
        return cleaned

    def clean_append_message(
        request,
        *,
        role: str,
        content: str,
        kind: str = "text",
        metadata: dict[str, object] | None = None,
    ):
        return original_append_message(
            request,
            role=role,
            content=content,
            kind=kind,
            metadata=_public_metadata(metadata),
        )

    conversational_views._messages = clean_messages
    conversational_views._append_message = clean_append_message
    conversational_views._vulnhunter_clean_chat_installed = True
    _INSTALLED = True
