"""Session-bound, resumable APK staging for forwarded web ports.

Large browser uploads are split into bounded requests before the completed file is
passed to the existing content-addressed APK ingestor. This avoids relying on a
single reverse-proxy request-body allowance while preserving the configured artifact
limit and archive validation performed by ``MobileArtifactIngestor``.
"""

from __future__ import annotations

import errno
import fcntl
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.db import DatabaseError

_SESSION_KEY = "vulnhunter_conversation_apk_uploads"
_UPLOAD_ID = re.compile(r"^upload-[0-9a-f]{32}$")
_DEFAULT_MAX_ACTIVE_UPLOADS = 3
_DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024
_DEFAULT_DISK_RESERVE_BYTES = 1024 * 1024 * 1024


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


def _configured_int(name: str, default: int) -> int:
    configured = getattr(settings, name, None)
    raw = configured if configured is not None else os.environ.get(name, str(default))
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ConversationUploadError(f"{name} must be an integer") from exc


def apk_upload_chunk_bytes() -> int:
    value = _configured_int(
        "VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES",
        _DEFAULT_CHUNK_BYTES,
    )
    if not 1 <= value <= 64 * 1024 * 1024:
        raise ConversationUploadError(
            "The APK upload chunk size must remain between 1 byte and 64 MiB."
        )
    return value


def _maximum_active_uploads() -> int:
    value = _configured_int(
        "VULNHUNTER_MOBILE_MAX_ACTIVE_UPLOADS",
        _DEFAULT_MAX_ACTIVE_UPLOADS,
    )
    if not 1 <= value <= 10:
        raise ConversationUploadError(
            "The active APK upload limit is invalid; it must remain between one and ten."
        )
    return value


def _upload_ttl_seconds() -> int:
    value = _configured_int("VULNHUNTER_MOBILE_UPLOAD_TTL_SECONDS", 3_600)
    if not 1 <= value <= 86_400:
        raise ConversationUploadError(
            "The APK upload expiry must remain between 1 second and 24 hours."
        )
    return value


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


def prune_stale_apk_uploads(*, now: float | None = None) -> int:
    """Delete abandoned staged files independently of a browser session."""

    instant = time.time() if now is None else now
    ttl = _upload_ttl_seconds()
    removed = 0
    for candidate in _upload_root().glob("upload-*.part"):
        try:
            if instant - candidate.stat().st_mtime > ttl:
                candidate.unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    return removed


def _prune(request: _Request) -> dict[str, dict[str, object]]:
    now = time.time()
    ttl = _upload_ttl_seconds()
    owner = _owner_id(request)
    retained: dict[str, dict[str, object]] = {}
    for upload_id, record in _records(request).items():
        try:
            created_at = float(record["created_at"])
            updated_at = float(record.get("updated_at", created_at))
            record_owner = str(record["owner_id"])
        except (KeyError, TypeError, ValueError):
            _unlink(upload_id)
            continue
        if record_owner != owner or now - updated_at > ttl:
            _unlink(upload_id)
            continue
        retained[upload_id] = record
    _save_records(request, retained)
    prune_stale_apk_uploads(now=now)
    return retained


def _owner_upload_records(
    request: _Request,
    current: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    """Collect live upload reservations across all durable workspaces for this user."""

    try:
        from vulnhunter.web.models import ConversationThread

        owner_pk = getattr(request.user, "pk", None)
        if owner_pk is None:
            return current
        now = time.time()
        ttl = _upload_ttl_seconds()
        combined: dict[str, dict[str, object]] = {}
        for data in ConversationThread.objects.filter(
            owner_id=owner_pk,
            archived=False,
        ).values_list("data", flat=True):
            if not isinstance(data, dict):
                continue
            raw = data.get(_SESSION_KEY)
            if not isinstance(raw, dict):
                continue
            for upload_id, record in raw.items():
                if not isinstance(upload_id, str) or not isinstance(record, dict):
                    continue
                try:
                    updated_at = float(record.get("updated_at", record["created_at"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if now - updated_at <= ttl and str(record.get("owner_id", "")) == _owner_id(request):
                    combined[upload_id] = dict(record)
        return combined or current
    except (DatabaseError, OSError, RuntimeError):
        return current


def _preflight_capacity(expected_bytes: int, records: dict[str, dict[str, object]]) -> None:
    root = _upload_root()
    maximum = int(settings.VULNHUNTER_MOBILE_MAX_APK_BYTES)
    staged_limit = _configured_int(
        "VULNHUNTER_MOBILE_MAX_STAGED_BYTES",
        maximum * 2,
    )
    if staged_limit < maximum:
        raise ConversationUploadError(
            "The staged APK quota must be at least as large as the maximum APK size."
        )
    staged_bytes = sum(
        max(0, int(record.get("expected_bytes", 0) or 0)) for record in records.values()
    )
    if staged_bytes + expected_bytes > staged_limit:
        raise ConversationUploadError(
            "The staged APK quota is full. Finish, cancel or allow an older upload to expire first."
        )

    reserve = _configured_int(
        "VULNHUNTER_MOBILE_MIN_FREE_BYTES",
        _DEFAULT_DISK_RESERVE_BYTES,
    )
    if reserve < 0:
        raise ConversationUploadError("The APK upload free-space reserve cannot be negative.")
    try:
        free = shutil.disk_usage(root).free
    except OSError as exc:
        raise ConversationUploadError(
            "Available storage could not be verified, so the APK upload did not start."
        ) from exc
    required = expected_bytes + reserve
    if free < required:
        raise ConversationUploadError(
            "There is not enough free storage to stage this APK safely. "
            f"Required at least {required} bytes; available {free} bytes."
        )


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
            f"The APK exceeds the configured {maximum} byte upload limit."
        )

    records = _prune(request)
    owner_records = _owner_upload_records(request, records)
    if len(owner_records) >= _maximum_active_uploads():
        raise ConversationUploadError(
            "Too many APK uploads are active across your workspaces. "
            "Finish or cancel one before starting another."
        )
    _preflight_capacity(expected_bytes, owner_records)

    upload_id = f"upload-{uuid4().hex}"
    path = _path(upload_id)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise ConversationUploadError(
                "Storage became full before the APK upload could start."
            ) from exc
        raise ConversationUploadError("The staged APK upload file could not be created.") from exc
    os.close(descriptor)

    instant = time.time()
    record: dict[str, object] = {
        "filename": safe_name,
        "expected_bytes": expected_bytes,
        "received_bytes": 0,
        "created_at": instant,
        "updated_at": instant,
        "owner_id": _owner_id(request),
    }
    records[upload_id] = record
    _save_records(request, records)
    return StagedApkUpload(upload_id, safe_name, expected_bytes, 0, path)


def get_apk_upload(request: _Request, *, upload_id: str) -> StagedApkUpload:
    """Return the authoritative resumable offset for one owned staged upload."""

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
    path = _path(upload_id)
    try:
        actual = path.stat().st_size
    except OSError as exc:
        discard_apk_upload(request, upload_id=upload_id)
        raise ConversationUploadError("The staged APK upload file is unavailable.") from exc
    if actual != received or received < 0 or received > expected:
        discard_apk_upload(request, upload_id=upload_id)
        raise ConversationUploadError("The staged APK upload offset failed integrity validation.")
    return StagedApkUpload(upload_id, filename, expected, received, path)


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

    maximum_chunk = apk_upload_chunk_bytes()
    payload = bytearray()
    for block in chunk.chunks():
        payload.extend(block)
        if len(payload) > maximum_chunk:
            raise ConversationUploadError("An APK upload chunk exceeded the configured chunk size.")
    if not payload:
        raise ConversationUploadError("The APK upload chunk is empty.")

    path = _path(upload_id)
    flags = os.O_RDWR | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        discard_apk_upload(request, upload_id=upload_id)
        if exc.errno == errno.ENOSPC:
            raise ConversationUploadError(
                "Storage became full while receiving the APK. The incomplete upload was removed."
            ) from exc
        raise ConversationUploadError("The staged APK upload file is unavailable.") from exc

    locked = False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        metadata = os.fstat(descriptor)
        actual_offset = metadata.st_size
        if actual_offset != offset:
            raise ConversationUploadError(
                f"The APK upload offset is out of sequence; expected {actual_offset} bytes."
            )
        next_received = actual_offset + len(payload)
        maximum = int(settings.VULNHUNTER_MOBILE_MAX_APK_BYTES)
        if next_received > expected or next_received > maximum:
            raise ConversationUploadError("The APK upload exceeded its declared size.")

        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError(errno.EIO, "the APK upload write made no progress")
            written += count
        os.fsync(descriptor)
    except ConversationUploadError:
        raise
    except OSError as exc:
        discard_apk_upload(request, upload_id=upload_id)
        if exc.errno == errno.ENOSPC:
            raise ConversationUploadError(
                "Storage became full while receiving the APK. The incomplete upload was removed."
            ) from exc
        raise ConversationUploadError(
            "The APK chunk could not be written safely; the incomplete upload was removed."
        ) from exc
    except Exception:
        discard_apk_upload(request, upload_id=upload_id)
        raise
    finally:
        if locked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)

    record["received_bytes"] = next_received
    record["updated_at"] = time.time()
    records[upload_id] = record
    _save_records(request, records)
    return StagedApkUpload(upload_id, filename, expected, next_received, path)


def discard_apk_upload(request: _Request, *, upload_id: str) -> None:
    records = _records(request)
    records.pop(upload_id, None)
    _save_records(request, records)
    _unlink(upload_id)
