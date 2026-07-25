"""Session-bound, resumable APK staging for forwarded web ports.

Large browser uploads are split into bounded requests before the completed file is
passed to the existing content-addressed APK ingestor.  This avoids relying on a
single reverse-proxy request-body allowance while preserving the one-gigabyte
artifact limit and all archive validation performed by ``MobileArtifactIngestor``.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile

_SESSION_KEY = "vulnhunter_conversation_apk_uploads"
_UPLOAD_ID = re.compile(r"^upload-[0-9a-f]{32}$")
_MAX_ACTIVE_UPLOADS = 3


class ConversationUploadError(ValueError):
    """A staged upload failed validation or no longer belongs to this session."""


class _Session(Protocol):
    modified: bool

    def get(self, key: str, default: object = None) -> object: ...

    def __setitem__(self, key: str, value: object) -> None: ...


class _Request(Protocol):
    session: _Session
    user: object


@dataclass(frozen=True)
class StagedApkUpload:
    upload_id: str
    filename: str
    expected_bytes: int
    received_bytes: int
    path: Path

    @property
    def complete(self) -> bool:
        return self.received_bytes == self.expected_bytes


def _upload_root() -> Path:
    root = (
        Path(settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT).expanduser().resolve()
        / ".conversation-uploads"
    )
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    return root


def _path(upload_id: str) -> Path:
    if not _UPLOAD_ID.fullmatch(upload_id):
        raise ConversationUploadError("The APK upload identifier is invalid.")
    return _upload_root() / f"{upload_id}.part"


def _records(request: _Request) -> dict[str, dict[str, object]]:
    raw = request.session.get(_SESSION_KEY, {})
    if not isinstance(raw, dict):
        return {}
    return {
        str(key): dict(value)
        for key, value in raw.items()
        if isinstance(key, str) and isinstance(value, dict)
    }


def _save_records(request: _Request, records: dict[str, dict[str, object]]) -> None:
    request.session[_SESSION_KEY] = records
    request.session.modified = True


def _owner_id(request: _Request) -> str:
    return str(getattr(request.user, "pk", ""))


def _safe_filename(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    safe = normalized.rsplit("/", 1)[-1].strip()
    if not safe or len(safe) > 240 or any(ord(character) < 32 for character in safe):
        raise ConversationUploadError("The APK filename is invalid.")
    if not safe.casefold().endswith(".apk"):
        raise ConversationUploadError("Choose a file with the .apk extension.")
    return safe


def _unlink(upload_id: str) -> None:
    try:
        _path(upload_id).unlink(missing_ok=True)
    except (ConversationUploadError, OSError):
        pass


def _prune(request: _Request) -> dict[str, dict[str, object]]:
    now = time.time()
    ttl = int(getattr(settings, "VULNHUNTER_MOBILE_UPLOAD_TTL_SECONDS", 3_600))
    owner = _owner_id(request)
    retained: dict[str, dict[str, object]] = {}
    for upload_id, record in _records(request).items():
        try:
            created_at = float(record["created_at"])
            record_owner = str(record["owner_id"])
        except (KeyError, TypeError, ValueError):
            _unlink(upload_id)
            continue
        if record_owner != owner or now - created_at > ttl:
            _unlink(upload_id)
            continue
        retained[upload_id] = record
    _save_records(request, retained)

    root = _upload_root()
    for candidate in root.glob("upload-*.part"):
        try:
            if now - candidate.stat().st_mtime > ttl:
                candidate.unlink(missing_ok=True)
        except OSError:
            continue
    return retained


def begin_apk_upload(
    request: _Request,
    *,
    filename: str,
    expected_bytes: int,
) -> StagedApkUpload:
    safe_name = _safe_filename(filename)
    maximum = int(settings.VULNHUNTER_MOBILE_MAX_APK_BYTES)
    if expected_bytes <= 0:
        raise ConversationUploadError("The APK upload is empty.")
    if expected_bytes > maximum:
        raise ConversationUploadError(
            f"The APK is larger than the configured {maximum} byte upload limit."
        )

    records = _prune(request)
    if len(records) >= _MAX_ACTIVE_UPLOADS:
        oldest = min(records, key=lambda key: float(records[key].get("created_at", 0)))
        records.pop(oldest, None)
        _unlink(oldest)

    upload_id = f"upload-{uuid4().hex}"
    path = _path(upload_id)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)

    record: dict[str, object] = {
        "filename": safe_name,
        "expected_bytes": expected_bytes,
        "received_bytes": 0,
        "created_at": time.time(),
        "owner_id": _owner_id(request),
    }
    records[upload_id] = record
    _save_records(request, records)
    return StagedApkUpload(upload_id, safe_name, expected_bytes, 0, path)


def append_apk_chunk(
    request: _Request,
    *,
    upload_id: str,
    offset: int,
    chunk: UploadedFile,
) -> StagedApkUpload:
    records = _prune(request)
    record = records.get(upload_id)
    if record is None or str(record.get("owner_id", "")) != _owner_id(request):
        raise ConversationUploadError("This APK upload is missing or has expired.")

    try:
        filename = str(record["filename"])
        expected = int(record["expected_bytes"])
        received = int(record["received_bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        discard_apk_upload(request, upload_id=upload_id)
        raise ConversationUploadError("The staged APK upload record is invalid.") from exc
    if offset != received:
        raise ConversationUploadError(
            f"The APK upload offset is out of sequence; expected {received} bytes."
        )

    maximum_chunk = int(settings.VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES)
    payload = bytearray()
    for block in chunk.chunks():
        payload.extend(block)
        if len(payload) > maximum_chunk:
            raise ConversationUploadError("An APK upload chunk exceeded the configured chunk size.")
    if not payload:
        raise ConversationUploadError("The APK upload chunk is empty.")
    next_received = received + len(payload)
    if next_received > expected or next_received > int(settings.VULNHUNTER_MOBILE_MAX_APK_BYTES):
        raise ConversationUploadError("The APK upload exceeded its declared size.")

    path = _path(upload_id)
    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        discard_apk_upload(request, upload_id=upload_id)
        raise ConversationUploadError("The staged APK upload file is unavailable.") from exc
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size != received:
            raise ConversationUploadError("The staged APK upload size no longer matches its session.")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        discard_apk_upload(request, upload_id=upload_id)
        raise
    else:
        os.close(descriptor)

    record["received_bytes"] = next_received
    records[upload_id] = record
    _save_records(request, records)
    return StagedApkUpload(upload_id, filename, expected, next_received, path)


def discard_apk_upload(request: _Request, *, upload_id: str) -> None:
    records = _records(request)
    records.pop(upload_id, None)
    _save_records(request, records)
    _unlink(upload_id)
