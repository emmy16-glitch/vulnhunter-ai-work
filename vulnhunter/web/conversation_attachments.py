"""Session-scoped references to safely ingested conversational attachments.

The uploaded bytes remain in the existing content-addressed artifact store. The
conversation session keeps only bounded, non-secret metadata and an opaque
attachment identifier.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from vulnhunter.mobile.models import MobileArtifactRecord

_SESSION_KEY = "vulnhunter_conversation_attachments"
_MAX_ATTACHMENTS = 8


class _Session(Protocol):
    modified: bool

    def get(self, key: str, default: object = None) -> object: ...

    def pop(self, key: str, default: object = None) -> object: ...

    def __setitem__(self, key: str, value: object) -> None: ...


class _SessionRequest(Protocol):
    session: _Session


@dataclass(frozen=True)
class ConversationAttachment:
    attachment_id: str
    kind: str
    artifact_id: str
    artifact_sha256: str
    original_filename: str
    size_bytes: int
    archive_entry_count: int
    dex_count: int
    native_library_count: int
    native_abis: tuple[str, ...]
    created_at: str

    def payload(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: object) -> ConversationAttachment | None:
        if not isinstance(payload, dict):
            return None
        try:
            return cls(
                attachment_id=str(payload["attachment_id"]),
                kind=str(payload["kind"]),
                artifact_id=str(payload["artifact_id"]),
                artifact_sha256=str(payload["artifact_sha256"]),
                original_filename=str(payload["original_filename"]),
                size_bytes=int(payload["size_bytes"]),
                archive_entry_count=int(payload["archive_entry_count"]),
                dex_count=int(payload["dex_count"]),
                native_library_count=int(payload["native_library_count"]),
                native_abis=tuple(str(item) for item in payload.get("native_abis", ())),
                created_at=str(payload["created_at"]),
            )
        except (KeyError, TypeError, ValueError):
            return None


def remember_apk_attachment(
    request: _SessionRequest,
    record: MobileArtifactRecord,
) -> ConversationAttachment:
    attachment = ConversationAttachment(
        attachment_id=f"attachment-{uuid4().hex[:20]}",
        kind="android_apk",
        artifact_id=record.artifact_id,
        artifact_sha256=record.sha256,
        original_filename=record.original_filename,
        size_bytes=record.size_bytes,
        archive_entry_count=record.archive_entry_count,
        dex_count=len(record.dex_entries),
        native_library_count=len(record.native_libraries),
        native_abis=record.native_abis,
        created_at=datetime.now(UTC).isoformat(),
    )
    raw = request.session.get(_SESSION_KEY, {})
    stored = dict(raw) if isinstance(raw, dict) else {}
    stored[attachment.attachment_id] = attachment.payload()
    ordered = sorted(
        stored.items(),
        key=lambda item: str(item[1].get("created_at", "")) if isinstance(item[1], dict) else "",
        reverse=True,
    )[:_MAX_ATTACHMENTS]
    request.session[_SESSION_KEY] = dict(ordered)
    request.session.modified = True
    return attachment


def get_attachment(
    request: _SessionRequest,
    attachment_id: str,
) -> ConversationAttachment | None:
    raw = request.session.get(_SESSION_KEY, {})
    if not isinstance(raw, dict):
        return None
    attachment = ConversationAttachment.from_payload(raw.get(attachment_id))
    if attachment is None or attachment.attachment_id != attachment_id:
        return None
    return attachment


def forget_attachment(request: _SessionRequest, attachment_id: str) -> None:
    raw = request.session.get(_SESSION_KEY, {})
    if not isinstance(raw, dict) or attachment_id not in raw:
        return
    stored = dict(raw)
    stored.pop(attachment_id, None)
    request.session[_SESSION_KEY] = stored
    request.session.modified = True


def clear_attachments(request: _SessionRequest) -> None:
    request.session.pop(_SESSION_KEY, None)
    request.session.modified = True
