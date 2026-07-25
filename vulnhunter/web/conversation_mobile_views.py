"""APK attachment and mobile-hunt endpoints for the conversational workspace."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_POST

from vulnhunter.mobile import MobileArtifactError, MobileArtifactIngestor
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.web.conversation_attachments import (
    ConversationAttachment,
    forget_attachment,
    get_attachment,
    remember_apk_attachment,
)
from vulnhunter.web.conversation_service import interpret_request
from vulnhunter.web.conversational_views import _actor, _append_message, _messages
from vulnhunter.web.mobile_conversation import build_mobile_chat_plan, mobile_plan_reply
from vulnhunter.web.mobile_conversation_state import (
    clear_mobile_plan,
    current_mobile_plan,
    mobile_chat_reply,
    remember_mobile_plan,
)
from vulnhunter.web.mobile_execution import enqueue_mobile_static_if_ready, mobile_static_status
from vulnhunter.web.services import WebPermissionDenied


def _ingestor() -> MobileArtifactIngestor:
    return MobileArtifactIngestor(
        Path(settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT),
        maximum_apk_bytes=settings.VULNHUNTER_MOBILE_MAX_APK_BYTES,
    )


def _resolve_artifact(attachment: ConversationAttachment) -> MobileArtifactRecord | None:
    for record in _ingestor().list_records():
        if (
            record.artifact_id == attachment.artifact_id
            and record.sha256 == attachment.artifact_sha256
        ):
            return record
    return None


def _conversation_context(request: HttpRequest) -> tuple[tuple[str, str], ...]:
    return tuple(
        (str(item.get("role", "")), str(item.get("content", "")))
        for item in _messages(request)[-8:]
        if isinstance(item, dict)
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def attachment_view(request: HttpRequest) -> JsonResponse:
    try:
        _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    uploaded = request.FILES.get("attachment")
    if uploaded is None:
        return JsonResponse({"detail": "Choose an Android APK to attach."}, status=400)
    try:
        record = _ingestor().ingest_chunks(uploaded.name, uploaded.chunks())
    except MobileArtifactError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    attachment = remember_apk_attachment(request, record)
    return JsonResponse(
        {
            "attachment": attachment.payload(),
            "message": (
                "APK validated and stored by content hash. No tool, emulator or network scan "
                "was started by the upload."
            ),
        }
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def mobile_message_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    text = request.POST.get("message", "").strip()
    if not text or len(text) > 4_000:
        return JsonResponse(
            {"detail": "Enter a message between 1 and 4,000 characters."},
            status=400,
        )
    attachment_id = request.POST.get("attachment_id", "").strip()
    attachment = get_attachment(request, attachment_id)
    if attachment is None or attachment.kind != "android_apk":
        return JsonResponse(
            {"detail": "The APK attachment is missing, expired or does not belong to this chat."},
            status=409,
        )
    artifact = _resolve_artifact(attachment)
    if artifact is None:
        return JsonResponse(
            {"detail": "The stored APK failed attachment-to-artifact verification."},
            status=409,
        )

    _append_message(
        request,
        role="user",
        content=text,
        metadata={"attachment": attachment.payload()},
    )
    requested_by = actor.governance_identity.reviewer_id
    plan = build_mobile_chat_plan(
        text=text,
        requested_by=requested_by,
        attachment=attachment,
        artifact=artifact,
    )
    execution = enqueue_mobile_static_if_ready(
        request,
        plan=plan,
        attachment=attachment,
        artifact=artifact,
        requested_by=requested_by,
    )
    if execution.get("state") == "queued":
        execution["status_url"] = reverse(
            "web-conversation-mobile-status",
            kwargs={"job_id": execution["job_id"]},
        )
    plan["execution"] = execution
    remember_mobile_plan(request, plan)
    message = _append_message(
        request,
        role="assistant",
        kind="mobile_plan",
        content=mobile_plan_reply(plan),
        metadata={
            "attachment": attachment.payload(),
            "mobile_plan": plan,
            "suggestions": [
                {
                    "label": "Explain the rounds",
                    "message": "Explain the mobile hunt rounds and what each one checks.",
                },
                {
                    "label": "Why is dynamic testing gated?",
                    "message": "Why is dynamic APK testing gated and what environment is required?",
                },
            ],
        },
    )
    forget_attachment(request, attachment_id)
    return JsonResponse({"message": message, "mobile_plan": plan})


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def mobile_followup_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.read")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    text = request.POST.get("message", "").strip()
    if not text or len(text) > 4_000:
        return JsonResponse(
            {"detail": "Enter a message between 1 and 4,000 characters."},
            status=400,
        )
    requested_by = actor.governance_identity.reviewer_id
    plan = current_mobile_plan(request, requested_by=requested_by)
    if plan is None:
        return JsonResponse({"detail": "No mobile hunt is selected in this conversation."}, status=404)
    interpreted = interpret_request(
        text,
        available_profiles=("static", "static_and_native", "dynamic", "full", "retest"),
        conversation_context=_conversation_context(request),
    )
    if interpreted.intent in {"scan", "authorize", "approve", "cancel"}:
        return JsonResponse({"handoff": True})

    _append_message(request, role="user", content=text)
    copy = mobile_chat_reply(
        text=text,
        intent=interpreted.intent,
        plan=plan,
        fallback=interpreted.assistant_copy,
    )
    message = _append_message(
        request,
        role="assistant",
        kind="result" if interpreted.intent == "results" else "text",
        content=copy,
        metadata={"provider": interpreted.provider, "mobile_plan_id": plan.get("plan_id")},
    )
    return JsonResponse({"message": message, "mobile_plan": plan})


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def mobile_context_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.read")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    plan = current_mobile_plan(
        request,
        requested_by=actor.governance_identity.reviewer_id,
    )
    return JsonResponse({"mobile_plan": plan})


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def mobile_context_reset_view(request: HttpRequest) -> JsonResponse:
    try:
        _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    clear_mobile_plan(request)
    return JsonResponse({"cleared": True})


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def mobile_status_view(request: HttpRequest, job_id: str) -> JsonResponse:
    try:
        actor = _actor(request, "scan.read")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    status = mobile_static_status(
        request,
        job_id=job_id,
        requested_by=actor.governance_identity.reviewer_id,
    )
    if status is None:
        return JsonResponse({"detail": "Mobile analysis job does not exist."}, status=404)
    return JsonResponse({"mobile_execution": status})
