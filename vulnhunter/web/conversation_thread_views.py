"""CRUD endpoints for durable conversational workspaces."""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_POST

from vulnhunter.web.conversation_threads import (
    ACTIVE_THREAD_SESSION_KEY,
    DEFAULT_TITLE,
    create_thread,
    list_threads,
    thread_summary,
    workspace_url,
)
from vulnhunter.web.models import ConversationThread


def _base_session(request: HttpRequest):
    return getattr(request, "vulnhunter_base_session", request.session)


def _owned_thread(request: HttpRequest, thread_id: str) -> ConversationThread | None:
    return ConversationThread.objects.filter(
        thread_id=thread_id,
        owner=request.user,
        archived=False,
    ).first()


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def thread_list_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {"threads": [thread_summary(item) for item in list_threads(request.user)]}
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def thread_create_view(request: HttpRequest) -> JsonResponse:
    title = request.POST.get("title", "").strip() or DEFAULT_TITLE
    thread = create_thread(owner=request.user, title=title)
    base_session = _base_session(request)
    base_session[ACTIVE_THREAD_SESSION_KEY] = str(thread.thread_id)
    base_session.modified = True
    payload = thread_summary(thread)
    payload["url"] = workspace_url(thread)
    return JsonResponse({"thread": payload}, status=201)


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def thread_rename_view(request: HttpRequest, thread_id: str) -> JsonResponse:
    thread = _owned_thread(request, thread_id)
    if thread is None:
        return JsonResponse({"detail": "That workspace does not exist."}, status=404)
    title = " ".join(request.POST.get("title", "").split()).strip()[:96]
    if not title:
        return JsonResponse({"detail": "Enter a workspace title."}, status=400)
    thread.title = title
    thread.save(update_fields=("title", "updated_at"))
    return JsonResponse({"thread": thread_summary(thread)})


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def thread_archive_view(request: HttpRequest, thread_id: str) -> JsonResponse:
    thread = _owned_thread(request, thread_id)
    if thread is None:
        return JsonResponse({"detail": "That workspace does not exist."}, status=404)
    thread.archived = True
    thread.save(update_fields=("archived", "updated_at"))
    replacement = (
        ConversationThread.objects.filter(owner=request.user, archived=False)
        .order_by("-updated_at")
        .first()
    )
    if replacement is None:
        replacement = create_thread(owner=request.user)
    base_session = _base_session(request)
    base_session[ACTIVE_THREAD_SESSION_KEY] = str(replacement.thread_id)
    base_session.modified = True
    return JsonResponse({"archived": True, "next_url": workspace_url(replacement)})
