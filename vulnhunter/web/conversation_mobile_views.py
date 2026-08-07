"""APK upload and mobile-hunt endpoints for the conversational workspace."""

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
from vulnhunter.web.conversation_threads import (
    maybe_title_thread,
    thread_memory,
    thread_preferences,
)
from vulnhunter.web.conversation_tools import build_safe_tool_context
from vulnhunter.web.conversation_upload_receipts import (
    get_apk_upload_completion,
    remember_apk_upload_completion,
)
from vulnhunter.web.conversation_uploads import (
    ConversationUploadError,
    append_apk_chunk,
    begin_apk_upload,
    discard_apk_upload,
    get_apk_upload,
)
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

_AUTO_ANALYSIS_TEXT = (
    "Run a full automatic security analysis of this APK using every available safe static and "
    "native tool. Record verified findings and list any approval-gated follow-up checks."
)


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


def _workspace_id(request: HttpRequest) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def _start_mobile_hunt(
    request: HttpRequest,
    *,
    actor: object,
    text: str,
    attachment: ConversationAttachment,
    artifact: MobileArtifactRecord,
) -> dict[str, object]:
    user_message = _append_message(
        request,
        role="user",
        content=text,
        metadata={"attachment": attachment.payload(), "automatic": text == _AUTO_ANALYSIS_TEXT},
    )
    requested_by = actor.governance_identity.reviewer_id
    plan = build_mobile_chat_plan(
        text=text,
        requested_by=requested_by,
        attachment=attachment,
        artifact=artifact,
        workspace_id=_workspace_id(request),
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
    forget_attachment(request, attachment.attachment_id)
    return {
        "attachment": attachment.payload(),
        "user_message": user_message,
        "message": message,
        "mobile_plan": plan,
        "auto_started": text == _AUTO_ANALYSIS_TEXT,
    }


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def upload_start_view(request: HttpRequest) -> JsonResponse:
    try:
        _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    filename = request.POST.get("filename", "").strip()
    try:
        expected_bytes = int(request.POST.get("size_bytes", ""))
        staged = begin_apk_upload(
            request,
            filename=filename,
            expected_bytes=expected_bytes,
        )
        maybe_title_thread(request, f"APK analysis · {staged.filename}")
    except (TypeError, ValueError, ConversationUploadError) as exc:
        detail = str(exc) or "The APK upload request is invalid."
        return JsonResponse({"detail": detail}, status=400)

    return JsonResponse(
        {
            "upload_id": staged.upload_id,
            "chunk_url": reverse(
                "web-conversation-upload-chunk",
                kwargs={"upload_id": staged.upload_id},
            ),
            "status_url": reverse(
                "web-conversation-upload-status",
                kwargs={"upload_id": staged.upload_id},
            ),
            "cancel_url": reverse(
                "web-conversation-upload-cancel",
                kwargs={"upload_id": staged.upload_id},
            ),
            "chunk_bytes": int(
                getattr(settings, "VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES", 8 * 1024 * 1024)
            ),
            "maximum_bytes": int(settings.VULNHUNTER_MOBILE_MAX_APK_BYTES),
            "received_bytes": 0,
            "auto_start": True,
        }
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def upload_chunk_view(request: HttpRequest, upload_id: str) -> JsonResponse:
    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    completion = get_apk_upload_completion(request, upload_id=upload_id)
    if completion is not None:
        return JsonResponse(completion)

    uploaded = request.FILES.get("chunk")
    if uploaded is None:
        return JsonResponse({"detail": "The APK upload chunk is missing."}, status=400)
    try:
        offset = int(request.POST.get("offset", ""))
        staged = append_apk_chunk(
            request,
            upload_id=upload_id,
            offset=offset,
            chunk=uploaded,
        )
    except (TypeError, ValueError, ConversationUploadError) as exc:
        return JsonResponse({"detail": str(exc) or "The APK upload chunk is invalid."}, status=409)

    if not staged.complete:
        return JsonResponse(
            {
                "upload_id": staged.upload_id,
                "received_bytes": staged.received_bytes,
                "expected_bytes": staged.expected_bytes,
                "complete": False,
            }
        )

    try:
        artifact = _ingestor().ingest_file(
            staged.path.resolve(strict=True),
            original_filename=staged.filename,
        )
    except (MobileArtifactError, OSError) as exc:
        discard_apk_upload(request, upload_id=upload_id)
        return JsonResponse({"detail": str(exc)}, status=400)
    discard_apk_upload(request, upload_id=upload_id)

    attachment = remember_apk_attachment(request, artifact)
    payload = _start_mobile_hunt(
        request,
        actor=actor,
        text=_AUTO_ANALYSIS_TEXT,
        attachment=attachment,
        artifact=artifact,
    )
    payload["upload"] = {
        "upload_id": upload_id,
        "received_bytes": staged.received_bytes,
        "expected_bytes": staged.expected_bytes,
        "complete": True,
    }
    payload = remember_apk_upload_completion(request, upload_id=upload_id, payload=payload)
    return JsonResponse(payload)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def upload_status_view(request: HttpRequest, upload_id: str) -> JsonResponse:
    try:
        _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    completion = get_apk_upload_completion(request, upload_id=upload_id)
    if completion is not None:
        return JsonResponse(completion)
    try:
        staged = get_apk_upload(request, upload_id=upload_id)
    except ConversationUploadError as exc:
        return JsonResponse({"detail": str(exc)}, status=404)
    return JsonResponse(
        {
            "upload_id": staged.upload_id,
            "filename": staged.filename,
            "received_bytes": staged.received_bytes,
            "expected_bytes": staged.expected_bytes,
            "complete": staged.complete,
        }
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def upload_cancel_view(request: HttpRequest, upload_id: str) -> JsonResponse:
    try:
        _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    try:
        get_apk_upload(request, upload_id=upload_id)
    except ConversationUploadError as exc:
        return JsonResponse({"detail": str(exc)}, status=404)
    discard_apk_upload(request, upload_id=upload_id)
    return JsonResponse({"cancelled": True, "upload_id": upload_id})


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def attachment_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.create")
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
    auto_start = request.POST.get("auto_start", "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if auto_start:
        return JsonResponse(
            _start_mobile_hunt(
                request,
                actor=actor,
                text=_AUTO_ANALYSIS_TEXT,
                attachment=attachment,
                artifact=record,
            )
        )
    return JsonResponse(
        {
            "attachment": attachment.payload(),
            "message": (
                "APK validated and stored by content hash. Send a mobile-analysis message to "
                "prepare and queue its governed tools."
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
    return JsonResponse(
        _start_mobile_hunt(
            request,
            actor=actor,
            text=text,
            attachment=attachment,
            artifact=artifact,
        )
    )


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
        return JsonResponse(
            {"detail": "No mobile hunt is selected in this conversation."}, status=404
        )
    reasoning_effort, provider_preference = thread_preferences(request)
    interpreted = interpret_request(
        text,
        available_profiles=("static", "static_and_native", "dynamic", "full", "retest"),
        conversation_context=_conversation_context(request),
        memory_summary=thread_memory(request),
        tool_context=build_safe_tool_context(request),
        reasoning_effort=reasoning_effort,
        provider_preference=provider_preference,
    )
    if interpreted.intent in {"scan", "authorize", "approve", "cancel"}:
        clear_mobile_plan(request)
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
        metadata={
            "provider": interpreted.provider,
            "model": interpreted.model,
            "reasoning_effort": interpreted.reasoning_effort,
            "mobile_plan_id": plan.get("plan_id"),
        },
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
