"""Durable, assessment-scoped completion receipts for resumable APK uploads."""

from __future__ import annotations

import time
from copy import deepcopy
from typing import Mapping

from django.conf import settings
from django.db import DatabaseError, transaction

from vulnhunter.web.models import ConversationThread

_COMPLETION_KEY = "vulnhunter_conversation_apk_upload_completions"
_DEFAULT_TTL_SECONDS = 3_600


def _ttl_seconds() -> int:
    configured = getattr(settings, "VULNHUNTER_MOBILE_UPLOAD_TTL_SECONDS", _DEFAULT_TTL_SECONDS)
    try:
        value = int(configured)
    except (TypeError, ValueError):
        return _DEFAULT_TTL_SECONDS
    return value if 1 <= value <= 86_400 else _DEFAULT_TTL_SECONDS


def _thread(request: object) -> ConversationThread | None:
    thread = getattr(request, "vulnhunter_thread", None)
    user = getattr(request, "user", None)
    if not isinstance(thread, ConversationThread) or getattr(user, "pk", None) is None:
        return None
    if thread.owner_id != user.pk or thread.archived:
        return None
    return thread


def _records(thread: ConversationThread) -> dict[str, dict[str, object]]:
    data = thread.data if isinstance(thread.data, dict) else {}
    raw = data.get(_COMPLETION_KEY, {})
    if not isinstance(raw, dict):
        return {}
    return {
        str(upload_id): dict(record)
        for upload_id, record in raw.items()
        if isinstance(upload_id, str) and isinstance(record, dict)
    }


def _live_records(
    records: Mapping[str, Mapping[str, object]],
    *,
    owner_id: str,
    now: float,
) -> dict[str, dict[str, object]]:
    ttl = _ttl_seconds()
    retained: dict[str, dict[str, object]] = {}
    for upload_id, record in records.items():
        try:
            completed_at = float(record["completed_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if str(record.get("owner_id", "")) != owner_id or now - completed_at > ttl:
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        retained[upload_id] = dict(record)
    return retained


def remember_apk_upload_completion(
    request: object,
    *,
    upload_id: str,
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Persist the exact successful response before returning it to the browser."""

    thread = _thread(request)
    if thread is None:
        raise RuntimeError("The active conversation workspace is unavailable.")
    owner_id = str(thread.owner_id)
    now = time.time()
    receipt_payload = deepcopy(dict(payload))
    with transaction.atomic():
        current = ConversationThread.objects.select_for_update().get(
            thread_id=thread.thread_id,
            owner_id=thread.owner_id,
            archived=False,
        )
        data = dict(current.data) if isinstance(current.data, dict) else {}
        records = _live_records(_records(current), owner_id=owner_id, now=now)
        existing = records.get(upload_id)
        if existing is not None:
            existing_payload = existing.get("payload")
            if existing_payload != receipt_payload:
                raise RuntimeError("The APK upload completion receipt does not match this result.")
            return deepcopy(existing_payload)
        records[upload_id] = {
            "owner_id": owner_id,
            "completed_at": now,
            "payload": receipt_payload,
        }
        data[_COMPLETION_KEY] = records
        current.data = data
        current.save(update_fields=("data", "updated_at"))
        thread.data = deepcopy(data)
        thread.updated_at = current.updated_at
    return deepcopy(receipt_payload)


def get_apk_upload_completion(
    request: object,
    *,
    upload_id: str,
) -> dict[str, object] | None:
    """Return a live completion receipt only for its owning workspace and user."""

    thread = _thread(request)
    if thread is None:
        return None
    owner_id = str(thread.owner_id)
    now = time.time()
    try:
        with transaction.atomic():
            current = ConversationThread.objects.select_for_update().get(
                thread_id=thread.thread_id,
                owner_id=thread.owner_id,
                archived=False,
            )
            data = dict(current.data) if isinstance(current.data, dict) else {}
            records = _live_records(_records(current), owner_id=owner_id, now=now)
            raw = data.get(_COMPLETION_KEY)
            if raw != records:
                if records:
                    data[_COMPLETION_KEY] = records
                else:
                    data.pop(_COMPLETION_KEY, None)
                current.data = data
                current.save(update_fields=("data", "updated_at"))
                thread.data = deepcopy(data)
                thread.updated_at = current.updated_at
            receipt = records.get(upload_id)
            payload = receipt.get("payload") if receipt is not None else None
            return deepcopy(payload) if isinstance(payload, dict) else None
    except (ConversationThread.DoesNotExist, DatabaseError):
        return None


__all__ = ["get_apk_upload_completion", "remember_apk_upload_completion"]
