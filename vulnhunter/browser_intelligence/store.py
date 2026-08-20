"""Owner-scoped persistence for Browser Intelligence sessions and evidence."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from vulnhunter.security import redact_mapping, redact_text

from .models import (
    BrowserActionReceipt,
    BrowserConsoleObservation,
    BrowserEvidenceArtifact,
    BrowserIntelligenceReport,
    BrowserNetworkObservation,
    BrowserSession,
)


class BrowserStoreError(RuntimeError):
    """Raised when browser state or evidence cannot be safely persisted."""


class BrowserIntelligenceStore:
    """Simple append-only, owner-scoped store suitable for a worker-backed V1."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise BrowserStoreError("browser store root must be a real directory")

    def save_session(self, session: BrowserSession) -> BrowserSession:
        path = self._session_dir(session.workspace_id, session.session_id) / "session.json"
        self._write_json(path, session.model_dump(mode="json"))
        return session

    def load_session(
        self,
        session_id: str,
        *,
        owner_id: str,
        workspace_id: str,
    ) -> BrowserSession:
        path = self._session_dir(workspace_id, session_id) / "session.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            session = BrowserSession.model_validate(payload)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrowserStoreError("browser session is unavailable") from exc
        if session.owner_id != owner_id or session.workspace_id != workspace_id:
            raise BrowserStoreError("browser session is not accessible to this owner/workspace")
        return session

    def append_receipt(
        self, receipt: BrowserActionReceipt, *, owner_id: str, session: BrowserSession
    ) -> None:
        self._assert_session_access(session, owner_id, receipt.session_id)
        self._append_jsonl(
            self._session_dir(session.workspace_id, session.session_id) / "receipts.jsonl",
            receipt.model_dump(mode="json"),
        )

    def append_network(
        self,
        observation: BrowserNetworkObservation,
        *,
        owner_id: str,
        session: BrowserSession,
    ) -> None:
        self._assert_session_access(session, owner_id, observation.source_session_id)
        self._append_jsonl(
            self._session_dir(session.workspace_id, session.session_id) / "network.jsonl",
            observation.model_dump(mode="json"),
        )

    def append_console(
        self,
        observation: BrowserConsoleObservation,
        *,
        owner_id: str,
        session: BrowserSession,
    ) -> None:
        self._assert_session_access(session, owner_id, observation.source_session_id)
        payload = observation.model_dump(mode="json")
        payload["message"] = redact_text(str(payload.get("message", "")))[:2_000]
        self._append_jsonl(
            self._session_dir(session.workspace_id, session.session_id) / "console.jsonl",
            payload,
        )

    def artifact_path(self, workspace_id: str, session_id: str, relative_path: str) -> Path:
        return self._safe_artifact_path(workspace_id, session_id, relative_path)

    def save_artifact(
        self,
        *,
        artifact: BrowserEvidenceArtifact,
        data: bytes,
        owner_id: str,
        session: BrowserSession,
    ) -> BrowserEvidenceArtifact:
        self._assert_session_access(session, owner_id, artifact.session_id)
        if len(data) != artifact.size_bytes:
            raise BrowserStoreError("browser artifact size does not match its metadata")
        actual = hashlib.sha256(data).hexdigest()
        if actual != artifact.sha256:
            raise BrowserStoreError("browser artifact digest does not match its metadata")
        destination = self._safe_artifact_path(
            session.workspace_id, session.session_id, artifact.relative_path
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".part")
        temporary.write_bytes(data)
        os.replace(temporary, destination)
        self._append_jsonl(
            self._session_dir(session.workspace_id, session.session_id) / "evidence.jsonl",
            artifact.model_dump(mode="json"),
        )
        return artifact

    def save_report(
        self, report: BrowserIntelligenceReport, *, owner_id: str, session: BrowserSession
    ) -> None:
        self._assert_session_access(session, owner_id, report.session_id)
        self._write_json(
            self._session_dir(session.workspace_id, session.session_id) / "report.json",
            report.model_dump(mode="json"),
        )

    def list_receipts(
        self, *, owner_id: str, session: BrowserSession
    ) -> tuple[BrowserActionReceipt, ...]:
        self._assert_session_access(session, owner_id, session.session_id)
        return tuple(
            BrowserActionReceipt.model_validate(payload)
            for payload in self._read_jsonl(
                self._session_dir(session.workspace_id, session.session_id) / "receipts.jsonl"
            )
        )

    def list_network(
        self, *, owner_id: str, session: BrowserSession
    ) -> tuple[BrowserNetworkObservation, ...]:
        """Return progressively persisted, owner-scoped network observations."""
        self._assert_session_access(session, owner_id, session.session_id)
        return tuple(
            BrowserNetworkObservation.model_validate(payload)
            for payload in self._read_jsonl(
                self._session_dir(session.workspace_id, session.session_id) / "network.jsonl"
            )
        )

    def list_console(
        self, *, owner_id: str, session: BrowserSession
    ) -> tuple[BrowserConsoleObservation, ...]:
        """Return progressively persisted, redacted console observations."""
        self._assert_session_access(session, owner_id, session.session_id)
        return tuple(
            BrowserConsoleObservation.model_validate(payload)
            for payload in self._read_jsonl(
                self._session_dir(session.workspace_id, session.session_id) / "console.jsonl"
            )
        )

    def load_report(
        self, *, owner_id: str, session: BrowserSession
    ) -> BrowserIntelligenceReport | None:
        """Return the persisted terminal report when one exists."""
        self._assert_session_access(session, owner_id, session.session_id)
        path = self._session_dir(session.workspace_id, session.session_id) / "report.json"
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return BrowserIntelligenceReport.model_validate(payload)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrowserStoreError("browser report is unavailable") from exc

    def _session_dir(self, workspace_id: str, session_id: str) -> Path:
        for value in (workspace_id, session_id):
            if not value or "/" in value or "\\" in value or value in {".", ".."}:
                raise BrowserStoreError("browser identifiers cannot be path components")
        path = self.root / workspace_id / session_id
        resolved = path.resolve()
        try:
            resolved.relative_to(self.root.resolve())
        except ValueError as exc:
            raise BrowserStoreError("browser session path escapes store root") from exc
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    def _safe_artifact_path(self, workspace_id: str, session_id: str, relative_path: str) -> Path:
        candidate = PurePosixPath(relative_path)
        if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
            raise BrowserStoreError("browser artifact path is unsafe")
        path = self._session_dir(workspace_id, session_id) / Path(*candidate.parts)
        resolved = path.resolve()
        try:
            resolved.relative_to(self._session_dir(workspace_id, session_id).resolve())
        except ValueError as exc:
            raise BrowserStoreError("browser artifact path escapes session root") from exc
        return resolved

    @staticmethod
    def _assert_session_access(session: BrowserSession, owner_id: str, session_id: str) -> None:
        if session.owner_id != owner_id or session.session_id != session_id:
            raise BrowserStoreError("browser state is not accessible to this owner/session")

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        payload = _safe_payload(payload)
        temporary = path.with_suffix(path.suffix + ".part")
        temporary.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        os.replace(temporary, path)

    @staticmethod
    def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
        safe = _safe_payload(payload)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(safe, sort_keys=True, separators=(",", ":")) + "\n")

    @staticmethod
    def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
        if not path.is_file():
            return ()
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
        return rows


_SAFE_ID_KEYS = {
    "action_id",
    "assessment_id",
    "attempt_id",
    "authorization_id",
    "evidence_id",
    "observation_id",
    "owner_id",
    "report_id",
    "session_id",
    "source_session_id",
    "workspace_id",
}


def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = redact_mapping(payload)
    if not isinstance(redacted, dict):
        raise BrowserStoreError("browser persistence payload is not an object")
    for key in _SAFE_ID_KEYS:
        if key in payload:
            redacted[key] = payload[key]
    return redacted


__all__ = ["BrowserIntelligenceStore", "BrowserStoreError"]
