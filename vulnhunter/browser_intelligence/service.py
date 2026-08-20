"""Orchestration for one authorized, bounded Browser Intelligence session."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from vulnhunter.scope.models import ApprovedTarget

from .models import (
    BrowserAction,
    BrowserActionReceipt,
    BrowserActionStatus,
    BrowserActionType,
    BrowserConsoleObservation,
    BrowserErrorCategory,
    BrowserEvidenceArtifact,
    BrowserIntelligenceReport,
    BrowserNetworkObservation,
    BrowserRuntimeName,
    BrowserSession,
    BrowserSessionState,
)
from .policy import BrowserPolicy, BrowserPolicyError
from .runtime import ObscuraMcpProcess, ObscuraRuntimeError
from .store import BrowserIntelligenceStore, BrowserStoreError


class BrowserIntelligenceError(RuntimeError):
    """Raised when the governed browser workflow fails closed."""


class BrowserIntelligenceService:
    def __init__(
        self,
        *,
        session: BrowserSession,
        target: ApprovedTarget,
        policy: BrowserPolicy,
        runtime: ObscuraMcpProcess,
        store: BrowserIntelligenceStore,
        owner_id: str,
        session_ttl_seconds: int = 900,
        activity_callback: Callable[[str, Mapping[str, object]], None] | None = None,
    ) -> None:
        self.session = session
        self.target = target
        self.policy = policy
        self.runtime = runtime
        self.store = store
        self.owner_id = owner_id
        self.session_ttl_seconds = session_ttl_seconds
        self.activity_callback = activity_callback
        self._consecutive_failures = 0
        self._last_action_signature: str | None = None
        self._repeated_action_count = 0
        self._receipts: list[BrowserActionReceipt] = []
        self._network: list[BrowserNetworkObservation] = []
        self._console: list[BrowserConsoleObservation] = []
        self._screenshots: list[BrowserEvidenceArtifact] = []

    @classmethod
    def create_session(
        cls,
        *,
        assessment_id: str,
        attempt_id: str | None,
        workspace_id: str,
        owner_id: str,
        authorization_id: str,
        target: ApprovedTarget,
        policy: BrowserPolicy,
        runtime: ObscuraMcpProcess,
        store: BrowserIntelligenceStore,
        now: datetime | None = None,
        session_ttl_seconds: int = 900,
        activity_callback: Callable[[str, Mapping[str, object]], None] | None = None,
    ) -> BrowserIntelligenceService:
        instant = (now or datetime.now(UTC)).astimezone(UTC)
        capabilities = runtime.start()
        session = BrowserSession(
            session_id=f"browser-{uuid4().hex[:16]}",
            assessment_id=assessment_id,
            attempt_id=attempt_id,
            workspace_id=workspace_id,
            owner_id=owner_id,
            authorization_id=authorization_id,
            target_url=target.normalized_url,
            allowed_origins=(f"{target.scheme}://{target.hostname}:{target.port}",),
            mode=policy.mode,
            runtime=BrowserRuntimeName.OBSCURA,
            runtime_version=capabilities.version,
            capabilities=capabilities,
            state=BrowserSessionState.READY,
            current_url=target.normalized_url,
            started_at=instant,
            last_activity=instant,
            expires_at=instant + timedelta(seconds=session_ttl_seconds),
        )
        store.save_session(session)
        service = cls(
            session=session,
            target=target,
            policy=policy,
            runtime=runtime,
            store=store,
            owner_id=owner_id,
            session_ttl_seconds=session_ttl_seconds,
            activity_callback=activity_callback,
        )
        service._emit(
            "browser_session_started", {"session_id": session.session_id, "runtime": "obscura"}
        )
        return service

    def execute_action(
        self, action: BrowserAction, *, now: datetime | None = None
    ) -> BrowserActionReceipt:
        instant = (now or datetime.now(UTC)).astimezone(UTC)
        action_id = f"browser-action-{uuid4().hex[:16]}"
        started = instant
        sequence = self.session.sequence + 1
        try:
            validated = self.policy.validate_action(action, session=self.session, now=instant)
            signature = (
                validated.action_type.value
                + ":"
                + json.dumps(dict(validated.parameters), sort_keys=True)
            )
            if signature == self._last_action_signature:
                self._repeated_action_count += 1
            else:
                self._last_action_signature = signature
                self._repeated_action_count = 1
            if self._repeated_action_count > self.policy.limits.maximum_repeated_action:
                raise BrowserPolicyError("repeated identical browser action limit exceeded")
            self._emit(
                "browser_action_started",
                {"action": validated.action_type.value, "sequence": sequence},
            )
            result = self.runtime.execute(validated)
            current_url = self.session.current_url
            if validated.action_type in {
                BrowserActionType.NAVIGATE,
                BrowserActionType.SNAPSHOT,
                BrowserActionType.READ_PAGE,
                BrowserActionType.GET_CURRENT_URL,
            }:
                current_url = self._current_url_from_result(result) or current_url
            if current_url and validated.action_type == BrowserActionType.NAVIGATE:
                self.policy.validate_url(current_url)
            evidence_ids = self._persist_action_observations(
                validated, result, sequence, current_url
            )
            summary = self._safe_summary(validated, result)
            completed = datetime.now(UTC)
            receipt = BrowserActionReceipt(
                action_id=action_id,
                session_id=self.session.session_id,
                assessment_id=self.session.assessment_id,
                workspace_id=self.session.workspace_id,
                sequence=sequence,
                action_type=validated.action_type,
                target_url=self._target_url_for_action(validated),
                current_url=current_url,
                started_at=started,
                completed_at=completed,
                status=BrowserActionStatus.COMPLETED,
                result_summary=summary,
                evidence_ids=tuple(evidence_ids),
            )
            self._consecutive_failures = 0
            self._update_session(
                state=BrowserSessionState.ACTIVE,
                current_url=current_url,
                action_count=self.session.action_count + 1,
                screenshot_count=self.session.screenshot_count
                + (1 if validated.action_type == BrowserActionType.TAKE_SCREENSHOT else 0),
                evidence_ids=tuple(dict.fromkeys((*self.session.evidence_ids, *evidence_ids))),
                sequence=sequence,
                last_activity=completed,
            )
            self._persist_receipt(receipt)
            self._emit(
                "browser_action_completed",
                {
                    "action": validated.action_type.value,
                    "sequence": sequence,
                    "evidence_ids": evidence_ids,
                },
            )
            return receipt
        except BrowserPolicyError as exc:
            return self._record_failure(
                action_id=action_id,
                sequence=sequence,
                action=action,
                started=started,
                status=BrowserActionStatus.BLOCKED,
                category=BrowserErrorCategory.POLICY_BLOCKED,
                message=str(exc),
            )
        except ObscuraRuntimeError as exc:
            return self._record_failure(
                action_id=action_id,
                sequence=sequence,
                action=action,
                started=started,
                status=BrowserActionStatus.FAILED,
                category=self._runtime_error_category(str(exc)),
                message=str(exc),
            )
        except (BrowserStoreError, ValueError) as exc:
            return self._record_failure(
                action_id=action_id,
                sequence=sequence,
                action=action,
                started=started,
                status=BrowserActionStatus.FAILED,
                category=BrowserErrorCategory.UNKNOWN,
                message=str(exc),
            )

    def finish(self, *, cancelled: bool = False) -> BrowserIntelligenceReport:
        state = BrowserSessionState.CANCELLED if cancelled else BrowserSessionState.COMPLETED
        self._update_session(state=state, last_activity=datetime.now(UTC))
        report = BrowserIntelligenceReport.build(
            report_id=f"browser-report-{uuid4().hex[:16]}",
            session_id=self.session.session_id,
            assessment_id=self.session.assessment_id,
            workspace_id=self.session.workspace_id,
            runtime=self.session.runtime,
            runtime_version=self.session.runtime_version,
            target_url=self.session.target_url,
            current_url=self.session.current_url,
            pages_visited=len(
                {receipt.current_url for receipt in self._receipts if receipt.current_url}
            ),
            forms_observed=sum(
                1
                for receipt in self._receipts
                if receipt.action_type == BrowserActionType.DETECT_FORMS
                and receipt.status == BrowserActionStatus.COMPLETED
            ),
            network_observations=tuple(self._network[-200:]),
            console_observations=tuple(self._console[-200:]),
            screenshots=tuple(self._screenshots),
            action_receipts=tuple(self._receipts),
            endpoint_paths=tuple(sorted({item.path for item in self._network})),
            limitations=("Obscura is a runtime observer; it does not verify vulnerabilities.",),
        )
        self.store.save_report(report, owner_id=self.owner_id, session=self.session)
        self.runtime.close()
        self._emit(
            "browser_session_finished",
            {"session_id": self.session.session_id, "state": state.value},
        )
        return report

    def cancel(self) -> BrowserIntelligenceReport:
        return self.finish(cancelled=True)

    def _persist_action_observations(
        self,
        action: BrowserAction,
        result: Mapping[str, Any],
        sequence: int,
        current_url: str | None,
    ) -> list[str]:
        evidence_ids: list[str] = []
        if action.action_type == BrowserActionType.GET_NETWORK_REQUESTS:
            self._network.extend(self._network_from_result(result))
        elif action.action_type == BrowserActionType.GET_CONSOLE_MESSAGES:
            self._console.extend(self._console_from_result(result))
        elif action.action_type == BrowserActionType.TAKE_SCREENSHOT:
            for index, image in enumerate(result.get("images", [])):
                if not isinstance(image, bytes):
                    continue
                evidence_id = f"browser-evidence-{uuid4().hex[:16]}"
                relative = f"screenshots/{sequence:04d}-{index:02d}.png"
                artifact = BrowserEvidenceArtifact(
                    evidence_id=evidence_id,
                    assessment_id=self.session.assessment_id,
                    attempt_id=self.session.attempt_id,
                    workspace_id=self.session.workspace_id,
                    session_id=self.session.session_id,
                    artifact_type="screenshot",
                    relative_path=relative,
                    sha256=hashlib.sha256(image).hexdigest(),
                    size_bytes=len(image),
                    media_type="image/png",
                    current_url=current_url,
                    captured_at=datetime.now(UTC),
                    runtime=BrowserRuntimeName.OBSCURA,
                    runtime_version=self.session.runtime_version,
                    viewport_width=_optional_int(action.parameters.get("width")),
                    viewport_height=_optional_int(action.parameters.get("height")),
                )
                self.store.save_artifact(
                    artifact=artifact, data=image, owner_id=self.owner_id, session=self.session
                )
                self._screenshots.append(artifact)
                evidence_ids.append(evidence_id)
        return evidence_ids

    def _network_from_result(self, result: Mapping[str, Any]) -> list[BrowserNetworkObservation]:
        rows = _decode_rows(result)
        observations: list[BrowserNetworkObservation] = []
        for row in rows[:200]:
            url = row.get("url") or row.get("request_url")
            if not isinstance(url, str):
                continue
            try:
                parsed = urlsplit(url)
                if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
                    continue
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                observations.append(
                    BrowserNetworkObservation(
                        observation_id=f"browser-network-{uuid4().hex[:16]}",
                        method=str(row.get("method", "GET")).upper()[:8],
                        scheme=parsed.scheme,
                        host=parsed.hostname.rstrip(".").casefold(),
                        port=port,
                        path=parsed.path or "/",
                        resource_type=str(row.get("resource_type", ""))[:80],
                        status_code=_optional_int(row.get("status_code") or row.get("status")),
                        initiator=str(row.get("initiator"))[:500] if row.get("initiator") else None,
                        same_origin=(
                            parsed.hostname.rstrip(".").casefold() == self.target.hostname
                            and port == self.target.port
                            and parsed.scheme == self.target.scheme
                        ),
                        request_body_present=bool(row.get("request_body_present", False)),
                        response_content_type=str(row.get("response_content_type"))[:160]
                        if row.get("response_content_type")
                        else None,
                        source_session_id=self.session.session_id,
                    )
                )
            except (TypeError, ValueError):
                continue
        return observations

    def _console_from_result(self, result: Mapping[str, Any]) -> list[BrowserConsoleObservation]:
        rows = _decode_rows(result)
        if not rows:
            text = result.get("text")
            if isinstance(text, str) and text.strip() and text.strip() != "No console messages.":
                rows = [{"level": "log", "message": text.strip()}]
        return [
            BrowserConsoleObservation(
                observation_id=f"browser-console-{uuid4().hex[:16]}",
                level=str(row.get("level", "log"))[:32],
                message=str(row.get("message", row.get("text", "")))[:2_000],
                source_url=str(row.get("url"))[:2_048] if row.get("url") else None,
                source_session_id=self.session.session_id,
            )
            for row in rows[:200]
            if isinstance(row, dict)
        ]

    def _record_failure(
        self,
        *,
        action_id: str,
        sequence: int,
        action: BrowserAction,
        started: datetime,
        status: BrowserActionStatus,
        category: BrowserErrorCategory,
        message: str,
    ) -> BrowserActionReceipt:
        self._consecutive_failures += 1
        completed = datetime.now(UTC)
        safe_message = " ".join(message.split())[:500]
        receipt = BrowserActionReceipt(
            action_id=action_id,
            session_id=self.session.session_id,
            assessment_id=self.session.assessment_id,
            workspace_id=self.session.workspace_id,
            sequence=sequence,
            action_type=action.action_type,
            target_url=self._target_url_for_action(action),
            current_url=self.session.current_url,
            started_at=started,
            completed_at=completed,
            status=status,
            result_summary={},
            error_category=category,
            error_message=safe_message,
        )
        self._persist_receipt(receipt)
        self._update_session(
            state=BrowserSessionState.FAILED
            if self._consecutive_failures >= self.policy.limits.maximum_consecutive_failures
            else BrowserSessionState.ACTIVE,
            action_count=self.session.action_count + 1,
            sequence=sequence,
            last_activity=completed,
        )
        self._emit(
            "browser_action_failed",
            {"action": action.action_type.value, "sequence": sequence, "category": category.value},
        )
        return receipt

    def _persist_receipt(self, receipt: BrowserActionReceipt) -> None:
        self.store.append_receipt(receipt, owner_id=self.owner_id, session=self.session)
        self._receipts.append(receipt)

    def _update_session(self, **changes: Any) -> None:
        self.session = self.session.model_copy(update=changes)
        self.store.save_session(self.session)

    def _emit(self, event: str, detail: Mapping[str, object]) -> None:
        if self.activity_callback is not None:
            self.activity_callback(event, detail)

    @staticmethod
    def _runtime_error_category(message: str) -> BrowserErrorCategory:
        lowered = message.casefold()
        if "timed out" in lowered:
            return (
                BrowserErrorCategory.ACTION_CANCELLED
                if "cancel" in lowered
                else BrowserErrorCategory.NAVIGATION_TIMEOUT
            )
        if "not found" in lowered or "missing" in lowered:
            return BrowserErrorCategory.SELECTOR_NOT_FOUND
        if "mcp" in lowered or "protocol" in lowered:
            return BrowserErrorCategory.PROTOCOL_ERROR
        return BrowserErrorCategory.RUNTIME_UNAVAILABLE

    @staticmethod
    def _current_url_from_result(result: Mapping[str, Any]) -> str | None:
        value = result.get("url") or result.get("current_url")
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            return value.split("?", 1)[0].split("#", 1)[0]
        text = result.get("text")
        if isinstance(text, str):
            match = re.search(r"https?://[^\s]+", text)
            if match:
                return match.group(0).rstrip(".,)")
        return None

    @staticmethod
    def _safe_summary(action: BrowserAction, result: Mapping[str, Any]) -> dict[str, Any]:
        text = result.get("text")
        summary: dict[str, Any] = {"action": action.action_type.value}
        if isinstance(text, str):
            summary["text_preview"] = " ".join(text.split())[:800]
        for key in ("url", "title", "count", "status"):
            if key in result and isinstance(result[key], (str, int, float, bool)):
                summary[key] = result[key]
        if "images" in result:
            summary["image_count"] = (
                len(result.get("images", [])) if isinstance(result.get("images"), list) else 0
            )
        return summary

    @staticmethod
    def _target_url_for_action(action: BrowserAction) -> str | None:
        value = action.parameters.get("url")
        return value if isinstance(value, str) else None


def _decode_rows(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = result.get("requests") or result.get("messages") or result.get("items")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    text = result.get("text")
    if not isinstance(text, str):
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return [row for row in parsed if isinstance(row, dict)]
    if isinstance(parsed, dict):
        for key in ("requests", "messages", "items"):
            if isinstance(parsed.get(key), list):
                return [row for row in parsed[key] if isinstance(row, dict)]
    rows = []
    for match in re.finditer(
        r"\[(?P<status>[0-9]{3})\]\s+(?P<method>[A-Z]+)\s+(?P<url>https?://[^\s]+)",
        text,
    ):
        rows.append(
            {
                "status": int(match.group("status")),
                "method": match.group("method"),
                "url": match.group("url").rstrip(")>,\"'"),
            }
        )
    return rows


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["BrowserIntelligenceError", "BrowserIntelligenceService"]
