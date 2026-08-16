"""Strict chat-first workspace experience hooks.

This module intentionally changes presentation/session behaviour only. Deterministic
security authorization, approval binding, scanner execution and evidence handling stay
inside their existing services.
"""

from __future__ import annotations

import re

_INSTALLED = False
_PRIVATE_MESSAGE_METADATA = frozenset({"provider", "model", "provider_detail"})
_RUN_REFERENCE = re.compile(
    r"\bassessment\s+run\s+([A-Za-z0-9][A-Za-z0-9._:-]{5,127})\b",
    re.IGNORECASE,
)


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
    """Keep chat clean, private and bound to explicitly referenced authorised runs."""

    global _INSTALLED
    if _INSTALLED:
        return

    from django.http import Http404, JsonResponse

    from vulnhunter.web import conversational_views

    original_append_message = conversational_views._append_message
    original_message_view = conversational_views.message_view

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

    def chat_first_message_view(request, *args, **kwargs):
        """Bind an explicit historical run reference before deterministic chat routing."""

        raw_message = str(request.POST.get("message", "")) if request.method == "POST" else ""
        referenced = _RUN_REFERENCE.search(raw_message)
        if referenced:
            run_id = referenced.group(1)
            try:
                actor = conversational_views._actor(request, "runs.view")
                run = conversational_views._visible_run(run_id, actor)
            except Http404:
                return JsonResponse(
                    {
                        "detail": (
                            "That assessment run is not available to this account. "
                            "Choose a visible run from conversation history."
                        )
                    },
                    status=404,
                )
            conversational_views._sync_state_from_run(
                request,
                conversational_views._state(request),
                run,
            )
        return original_message_view(request, *args, **kwargs)

    conversational_views._messages = clean_messages
    conversational_views._append_message = clean_append_message
    conversational_views.message_view = chat_first_message_view
    conversational_views._vulnhunter_clean_chat_installed = True
    conversational_views._vulnhunter_run_reference_installed = True
    _INSTALLED = True
