"""Durable, user-owned conversation workspaces and session compatibility.

The existing conversational services use ``request.session`` for bounded state. This
module isolates those keys per durable thread while delegating authentication and all
other Django session data to the original session backend.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from django.db import transaction
from django.urls import reverse

from vulnhunter.web.models import ConversationThread

ACTIVE_THREAD_SESSION_KEY = "vulnhunter_active_conversation_thread"
SCOPED_SESSION_KEYS = frozenset(
    {
        "vulnhunter_conversation_messages",
        "vulnhunter_conversation_state",
        "vulnhunter_conversation_attachments",
        "vulnhunter_conversation_mobile_plan",
        "vulnhunter_conversation_mobile_jobs",
        "vulnhunter_mobile_extension_jobs",
        "vulnhunter_conversation_apk_uploads",
        "vulnhunter_conversation_source_hunt",
    }
)
DEFAULT_TITLE = "New security workspace"
REQUIRED_REASONING_EFFORT = "high"
DEFAULT_PROVIDER_PREFERENCE = "groq"
LEGACY_REASONING_EFFORTS = frozenset({"low", "medium", "high"})
PROVIDER_PREFERENCES = frozenset({"auto", "groq", "huggingface"})


class ConversationThreadNotFound(LookupError):
    """The requested thread does not exist for this authenticated user."""


def _clean_title(value: str) -> str:
    normalized = " ".join(value.split()).strip()
    return normalized[:96] or DEFAULT_TITLE


def _provided_thread_id(request: object) -> str | None:
    headers = getattr(request, "headers", {})
    candidate = str(headers.get("X-VulnHunter-Thread", "") or "").strip()
    if not candidate:
        candidate = str(getattr(request, "GET", {}).get("thread", "") or "").strip()
    if not candidate and getattr(request, "method", "GET") == "POST":
        candidate = str(getattr(request, "POST", {}).get("thread_id", "") or "").strip()
    if not candidate:
        return None
    try:
        return str(UUID(candidate))
    except (TypeError, ValueError):
        raise ConversationThreadNotFound("The selected workspace identifier is invalid.") from None


def _legacy_data(session: object) -> dict[str, object]:
    migrated: dict[str, object] = {}
    for key in SCOPED_SESSION_KEYS:
        value = session.get(key, None)
        if value is not None:
            migrated[key] = deepcopy(value)
    return migrated


def _clear_legacy_data(session: object) -> None:
    for key in SCOPED_SESSION_KEYS:
        session.pop(key, None)
    session.modified = True


def _effective_provider(value: str | None) -> str:
    """Resolve legacy automatic preference without enabling runtime fallback."""

    normalized = str(value or "").strip().casefold()
    if normalized == "huggingface":
        return "huggingface"
    return DEFAULT_PROVIDER_PREFERENCE


def create_thread(*, owner: object, title: str = DEFAULT_TITLE) -> ConversationThread:
    return ConversationThread.objects.create(
        owner=owner,
        title=_clean_title(title),
        data={},
        reasoning_effort=REQUIRED_REASONING_EFFORT,
        provider_preference=DEFAULT_PROVIDER_PREFERENCE,
    )


def resolve_thread(request: object) -> ConversationThread:
    """Resolve an explicitly selected, active, latest, or newly created thread."""

    user = request.user
    base_session = request.session
    explicit = _provided_thread_id(request)
    thread: ConversationThread | None = None
    if explicit:
        thread = ConversationThread.objects.filter(
            thread_id=explicit,
            owner=user,
            archived=False,
        ).first()
        if thread is None:
            raise ConversationThreadNotFound("That workspace does not exist or is unavailable.")
    else:
        active = str(base_session.get(ACTIVE_THREAD_SESSION_KEY, "") or "").strip()
        if active:
            thread = ConversationThread.objects.filter(
                thread_id=active,
                owner=user,
                archived=False,
            ).first()
        if thread is None:
            thread = (
                ConversationThread.objects.filter(owner=user, archived=False)
                .order_by("-updated_at", "-created_at")
                .first()
            )

    if thread is None:
        legacy = _legacy_data(base_session)
        thread = ConversationThread.objects.create(
            owner=user,
            title=DEFAULT_TITLE,
            data=legacy,
            reasoning_effort=REQUIRED_REASONING_EFFORT,
            provider_preference=DEFAULT_PROVIDER_PREFERENCE,
        )
        if legacy:
            _clear_legacy_data(base_session)

    base_session[ACTIVE_THREAD_SESSION_KEY] = str(thread.thread_id)
    base_session.modified = True
    return thread


def list_threads(owner: object, *, limit: int = 30) -> tuple[ConversationThread, ...]:
    safe_limit = max(1, min(int(limit), 100))
    return tuple(
        ConversationThread.objects.filter(owner=owner, archived=False).order_by(
            "-updated_at", "-created_at"
        )[:safe_limit]
    )


def workspace_url(thread: ConversationThread) -> str:
    return f"{reverse('web-dashboard')}?thread={thread.thread_id}"


def thread_summary(thread: ConversationThread) -> dict[str, object]:
    data = thread.data if isinstance(thread.data, dict) else {}
    state = data.get("vulnhunter_conversation_state")
    state = state if isinstance(state, dict) else {}
    mobile_plan = data.get("vulnhunter_conversation_mobile_plan")
    mobile_plan = mobile_plan if isinstance(mobile_plan, dict) else {}
    mobile_execution = mobile_plan.get("execution")
    mobile_execution = mobile_execution if isinstance(mobile_execution, dict) else {}
    source_plan = data.get("vulnhunter_conversation_source_hunt")
    source_plan = source_plan if isinstance(source_plan, dict) else {}
    source_execution = source_plan.get("execution")
    source_execution = source_execution if isinstance(source_execution, dict) else {}
    uploads = data.get("vulnhunter_conversation_apk_uploads")
    uploads = uploads if isinstance(uploads, dict) else {}
    status = str(
        source_execution.get("state")
        or mobile_execution.get("state")
        or state.get("state")
        or ("active" if state.get("run_id") else "idle")
    )
    if uploads:
        status = "uploading"
    return {
        "thread_id": str(thread.thread_id),
        "title": thread.title,
        "updated_at": thread.updated_at.isoformat(),
        "status": status,
        "upload_count": len(uploads),
        "reasoning_effort": REQUIRED_REASONING_EFFORT,
        "provider_preference": _effective_provider(thread.provider_preference),
        "url": workspace_url(thread),
    }


def maybe_title_thread(request: object, value: str) -> None:
    thread = getattr(request, "vulnhunter_thread", None)
    if not isinstance(thread, ConversationThread) or thread.title != DEFAULT_TITLE:
        return
    title = _clean_title(value)
    if title == DEFAULT_TITLE:
        return
    ConversationThread.objects.filter(
        thread_id=thread.thread_id,
        owner=thread.owner,
        title=DEFAULT_TITLE,
    ).update(title=title)
    thread.title = title


@dataclass
class ThreadSessionProxy:
    """Route only conversation keys to one durable thread."""

    base_session: object
    thread: ConversationThread

    def __post_init__(self) -> None:
        self._cache = deepcopy(self.thread.data if isinstance(self.thread.data, dict) else {})

    @property
    def modified(self) -> bool:
        return bool(getattr(self.base_session, "modified", False))

    @modified.setter
    def modified(self, value: bool) -> None:
        self.base_session.modified = value

    def _scoped(self, key: str) -> bool:
        return key in SCOPED_SESSION_KEYS

    def _write(self, key: str, value: object) -> None:
        with transaction.atomic():
            current = ConversationThread.objects.select_for_update().get(
                thread_id=self.thread.thread_id,
                owner=self.thread.owner,
                archived=False,
            )
            data = dict(current.data) if isinstance(current.data, dict) else {}
            data[key] = deepcopy(value)
            current.data = data
            current.save(update_fields=("data", "updated_at"))
            self.thread.updated_at = current.updated_at
        self._cache[key] = deepcopy(value)

    def _remove(self, key: str, default: object = None) -> object:
        with transaction.atomic():
            current = ConversationThread.objects.select_for_update().get(
                thread_id=self.thread.thread_id,
                owner=self.thread.owner,
                archived=False,
            )
            data = dict(current.data) if isinstance(current.data, dict) else {}
            value = data.pop(key, default)
            if data != current.data:
                current.data = data
                current.save(update_fields=("data", "updated_at"))
                self.thread.updated_at = current.updated_at
        self._cache.pop(key, None)
        return deepcopy(value)

    def __getitem__(self, key: str) -> object:
        if self._scoped(key):
            if key not in self._cache:
                raise KeyError(key)
            return deepcopy(self._cache[key])
        return self.base_session[key]

    def __setitem__(self, key: str, value: object) -> None:
        if self._scoped(key):
            self._write(key, value)
            return
        self.base_session[key] = value

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str) and self._scoped(key):
            return key in self._cache
        return key in self.base_session

    def get(self, key: str, default: object = None) -> object:
        if self._scoped(key):
            return deepcopy(self._cache.get(key, default))
        return self.base_session.get(key, default)

    def pop(self, key: str, default: object = None) -> object:
        if self._scoped(key):
            return self._remove(key, default)
        return self.base_session.pop(key, default)

    def setdefault(self, key: str, default: object = None) -> object:
        if self._scoped(key):
            if key not in self._cache:
                self._write(key, default)
            return deepcopy(self._cache[key])
        return self.base_session.setdefault(key, default)

    def keys(self):
        return set(self.base_session.keys()) | set(self._cache.keys())

    def items(self):
        return [(key, self.get(key)) for key in self.keys()]

    def __iter__(self):
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self.keys())

    def __getattr__(self, name: str) -> Any:
        return getattr(self.base_session, name)


def thread_preferences(request: object) -> tuple[str, str]:
    """Return the enforced high-reasoning policy for this workspace.

    Legacy ``low``/``medium`` effort and ``auto`` provider values remain readable,
    but they cannot lower reasoning quality or enable automatic provider failover.
    """

    thread = getattr(request, "vulnhunter_thread", None)
    if not isinstance(thread, ConversationThread):
        return REQUIRED_REASONING_EFFORT, DEFAULT_PROVIDER_PREFERENCE
    return REQUIRED_REASONING_EFFORT, _effective_provider(thread.provider_preference)


def update_thread_preferences(
    request: object,
    *,
    reasoning_effort: str | None = None,
    provider_preference: str | None = None,
) -> ConversationThread:
    thread = getattr(request, "vulnhunter_thread", None)
    if not isinstance(thread, ConversationThread):
        raise ConversationThreadNotFound("The active workspace is unavailable.")

    requested_effort = (reasoning_effort or REQUIRED_REASONING_EFFORT).strip().casefold()
    if requested_effort not in LEGACY_REASONING_EFFORTS:
        raise ValueError("Reasoning effort must be low, medium, or high.")
    effort = REQUIRED_REASONING_EFFORT

    requested_provider = (provider_preference or thread.provider_preference or "auto").strip().casefold()
    if requested_provider not in PROVIDER_PREFERENCES:
        raise ValueError("Provider preference must be automatic, Groq, or Hugging Face.")
    provider = _effective_provider(requested_provider)

    with transaction.atomic():
        current = ConversationThread.objects.select_for_update().get(
            thread_id=thread.thread_id,
            owner=thread.owner,
            archived=False,
        )
        current.reasoning_effort = effort
        current.provider_preference = provider
        current.save(update_fields=("reasoning_effort", "provider_preference", "updated_at"))
    thread.reasoning_effort = effort
    thread.provider_preference = provider
    thread.updated_at = current.updated_at
    return thread


def refresh_thread_memory(request: object, messages: list[dict[str, object]]) -> str:
    """Persist a compact, deterministic rolling summary for later model context."""

    thread = getattr(request, "vulnhunter_thread", None)
    if not isinstance(thread, ConversationThread):
        return ""
    lines: list[str] = []
    for item in messages[-80:]:
        role = str(item.get("role", "")).strip()
        content = " ".join(str(item.get("content", "")).split()).strip()
        if role not in {"user", "assistant"} or not content:
            continue
        label = "User" if role == "user" else "Assistant"
        lines.append(f"{label}: {content[:900]}")
    summary = "\n".join(lines)
    if len(summary) > 12_000:
        pinned = "\n".join(lines[:8])
        remaining = max(0, 12_000 - len(pinned) - 1)
        recent = "\n".join(lines[8:])[-remaining:]
        first_break = recent.find("\n")
        if first_break >= 0:
            recent = recent[first_break + 1 :]
        summary = f"{pinned}\n{recent}".strip()
    if summary == thread.memory_summary:
        return summary
    ConversationThread.objects.filter(
        thread_id=thread.thread_id,
        owner=thread.owner,
        archived=False,
    ).update(memory_summary=summary)
    thread.memory_summary = summary
    return summary


def thread_memory(request: object) -> str:
    thread = getattr(request, "vulnhunter_thread", None)
    if not isinstance(thread, ConversationThread):
        return ""
    return str(thread.memory_summary or "")[:12_000]
