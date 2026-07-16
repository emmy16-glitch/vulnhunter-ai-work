"""Deterministic report artifact builder."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from vulnhunter.actions.models import sha256_json
from vulnhunter.reports.models import ReportArtifact, ReportKind

_PROTECTED_KEYS = {
    "credential",
    "credentials",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "authorization",
    "cookie",
    "set_cookie",
    "session_id",
    "session_token",
    "private_key",
    "password",
    "secret",
    "chain_of_thought",
}
_SCALAR_TYPES = (str, int, float, bool, type(None))


def build_report_artifact(
    *,
    report_id: str,
    kind: ReportKind,
    payload: dict[str, object],
    provenance: tuple[str, ...],
) -> ReportArtifact:
    _reject_protected_payload(payload, seen=set())
    return ReportArtifact(
        report_id=report_id,
        kind=kind,
        payload_sha256=sha256_json(payload),
        provenance=provenance,
    )


def _normalize_key(key: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    return re.sub(r"_+", "_", normalized)


def _reject_protected_payload(value: object, *, seen: set[int]) -> None:
    if isinstance(value, _SCALAR_TYPES):
        return
    identity = id(value)
    if identity in seen:
        raise ValueError("report payload contains unsupported cyclic data")
    seen.add(identity)
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("report payload contains unsupported non-string keys")
            if _normalize_key(key) in _PROTECTED_KEYS:
                raise ValueError("report payload contains protected fields")
            _reject_protected_payload(item, seen=seen)
        seen.remove(identity)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _reject_protected_payload(item, seen=seen)
        seen.remove(identity)
        return
    raise ValueError("report payload contains unsupported data")
