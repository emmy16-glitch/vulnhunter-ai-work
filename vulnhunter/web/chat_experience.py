"""Strict chat-first workspace experience hooks.

This module intentionally changes presentation/session behaviour only. Deterministic
security authorization, approval binding, scanner execution and evidence handling stay
inside their existing services.
"""

from __future__ import annotations

_INSTALLED = False


def install() -> None:
    """Remove synthetic assistant seed messages from empty conversation threads."""

    global _INSTALLED
    if _INSTALLED:
        return

    from vulnhunter.web import conversational_views

    def clean_messages(request):
        raw = request.session.get(conversational_views._SESSION_MESSAGES, [])
        if not isinstance(raw, list):
            raw = []
        return [
            item for item in raw if isinstance(item, dict)
        ][-conversational_views._MAX_MESSAGES :]

    conversational_views._messages = clean_messages
    conversational_views._vulnhunter_clean_chat_installed = True
    _INSTALLED = True
