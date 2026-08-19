"""Typed, immutable contracts for governed browser intelligence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class BrowserRuntimeName(StrEnum):
    OBSCURA = "obscura"
    PLAYWRIGHT = "playwright"


class BrowserSessionState(StrEnum):
    QUEUED = "queued"
    STARTING = "starting"
    READY = "ready"
    NAVIGATING = "navigating"
    ACTIVE = "active"
    WAITING = "waiting"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    EXPIRED = "expired"


class BrowserMode(StrEnum):
    PASSIVE = "passive"
    CONTROLLED_INTERACTIVE = "controlled_interactive"


class BrowserActionType(StrEnum):
    NAVIGATE = "navigate"
    SNAPSHOT = "snapshot"
    READ_PAGE = "read_page"
    GET_LINKS = "get_links"
    GET_INTERACTIVE_ELEMENTS = "get_interactive_elements"
    DETECT_FORMS = "detect_forms"
    GET_ATTRIBUTE = "get_attribute"
    COUNT = "count"
    SEARCH_TEXT = "search_text"
    CLICK = "click"
    FILL = "fill"
    TYPE = "type"
    PRESS_KEY = "press_key"
    SELECT_OPTION = "select_option"
    SCROLL = "scroll"
    WAIT = "wait"
    WAIT_FOR_TEXT = "wait_for_text"
    GET_NETWORK_REQUESTS = "get_network_requests"
    GET_CONSOLE_MESSAGES = "get_console_messages"
    TAKE_SCREENSHOT = "take_screenshot"
    GET_CURRENT_URL = "get_current_url"


class BrowserActionStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BrowserErrorCategory(StrEnum):
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    STARTUP_FAILURE = "startup_failure"
    STARTUP_TIMEOUT = "startup_timeout"
    NAVIGATION_TIMEOUT = "navigation_timeout"
    SELECTOR_NOT_FOUND = "selector_not_found"
    STALE_ELEMENT = "stale_element"
    SCOPE_BLOCKED = "scope_blocked"
    REDIRECT_BLOCKED = "redirect_blocked"
    TARGET_UNAVAILABLE = "target_unavailable"
    CONSOLE_EXTRACTION_FAILURE = "console_extraction_failure"
    SCREENSHOT_FAILURE = "screenshot_failure"
    SESSION_EXPIRED = "session_expired"
    ACTION_CANCELLED = "action_cancelled"
    POLICY_BLOCKED = "policy_blocked"
    PROTOCOL_ERROR = "protocol_error"
    UNKNOWN = "unknown"


class BrowserRuntimeCapabilities(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    runtime: BrowserRuntimeName
    version: str
    mcp_available: bool = False
    screenshot_available: bool = False
    network_available: bool = False
    console_available: bool = False
    forms_available: bool = False
    interactive_elements_available: bool = False
    evaluate_available: bool = False
    preflight_passed: bool = False
    reason: str = Field(default="", max_length=500)


class BrowserAction(BaseModel):
    """AI proposal accepted only after BrowserPolicy validates it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_type: BrowserActionType
    parameters: Mapping[str, Any] = Field(default_factory=dict)
    requested_by: str = Field(min_length=1, max_length=128)
    client_action_id: str | None = Field(default=None, max_length=128)

    @field_validator("requested_by")
    @classmethod
    def normalize_requester(cls, value: str) -> str:
        return value.strip()[:128]


class BrowserActionReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    session_id: str
    assessment_id: str
    workspace_id: str
    sequence: int = Field(ge=1)
    action_type: BrowserActionType
    target_url: str | None = Field(default=None, max_length=2_048)
    current_url: str | None = Field(default=None, max_length=2_048)
    started_at: datetime
    completed_at: datetime
    status: BrowserActionStatus
    result_summary: Mapping[str, Any] = Field(default_factory=dict)
    evidence_ids: tuple[str, ...] = ()
    error_category: BrowserErrorCategory | None = None
    error_message: str | None = Field(default=None, max_length=500)

    @field_validator("started_at", "completed_at")
    @classmethod
    def aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("browser receipt timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("action_id", "session_id", "assessment_id", "workspace_id")
    @classmethod
    def stable_ids(cls, value: str) -> str:
        normalized = value.strip().lower()
        if _IDENTIFIER.fullmatch(normalized) is None:
            raise ValueError("browser receipt identifiers must be stable lowercase values")
        return normalized

    @model_validator(mode="after")
    def validate_terminal_error(self):
        if self.status in {BrowserActionStatus.BLOCKED, BrowserActionStatus.FAILED}:
            if self.error_category is None:
                raise ValueError("blocked or failed browser actions require an error category")
        return self


class BrowserNetworkObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: str
    method: str = Field(max_length=8)
    scheme: str = Field(max_length=8)
    host: str = Field(max_length=253)
    port: int = Field(ge=1, le=65_535)
    path: str = Field(max_length=2_048)
    resource_type: str = Field(default="", max_length=80)
    status_code: int | None = Field(default=None, ge=100, le=599)
    initiator: str | None = Field(default=None, max_length=500)
    same_origin: bool
    request_body_present: bool = False
    response_content_type: str | None = Field(default=None, max_length=160)
    source_session_id: str
    evidence_id: str | None = None

    @field_validator("observation_id", "source_session_id", "evidence_id")
    @classmethod
    def validate_ids(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if _IDENTIFIER.fullmatch(normalized) is None:
            raise ValueError("browser observation identifiers must be stable lowercase values")
        return normalized

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()


class BrowserConsoleObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: str
    level: str = Field(max_length=32)
    message: str = Field(max_length=2_000)
    source_url: str | None = Field(default=None, max_length=2_048)
    source_session_id: str
    evidence_id: str | None = None


class BrowserEvidenceArtifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    assessment_id: str
    attempt_id: str | None = None
    workspace_id: str
    session_id: str
    artifact_type: str = Field(min_length=3, max_length=64)
    relative_path: str
    sha256: str
    size_bytes: int = Field(ge=0, le=20_000_000)
    media_type: str = Field(min_length=3, max_length=128)
    current_url: str | None = Field(default=None, max_length=2_048)
    viewport_width: int | None = Field(default=None, ge=1, le=32_768)
    viewport_height: int | None = Field(default=None, ge=1, le=32_768)
    captured_at: datetime
    runtime: BrowserRuntimeName
    runtime_version: str

    @field_validator("sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("browser evidence hash must be SHA-256")
        return value

    @field_validator("captured_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("browser evidence capture time must be timezone-aware")
        return value.astimezone(UTC)


class BrowserSession(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    assessment_id: str
    attempt_id: str | None = None
    workspace_id: str
    owner_id: str
    authorization_id: str
    target_url: str
    allowed_origins: tuple[str, ...]
    mode: BrowserMode = BrowserMode.PASSIVE
    runtime: BrowserRuntimeName
    runtime_version: str
    capabilities: BrowserRuntimeCapabilities
    state: BrowserSessionState = BrowserSessionState.QUEUED
    current_url: str | None = None
    started_at: datetime
    last_activity: datetime
    expires_at: datetime
    action_count: int = Field(default=0, ge=0)
    screenshot_count: int = Field(default=0, ge=0)
    evidence_ids: tuple[str, ...] = ()
    sequence: int = Field(default=0, ge=0)

    @field_validator("started_at", "last_activity", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("browser session timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_expiry(self):
        if self.expires_at <= self.started_at:
            raise ValueError("browser session expiry must be after startup")
        if not self.allowed_origins:
            raise ValueError("browser sessions require at least one allowed origin")
        return self


class BrowserIntelligenceReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str
    session_id: str
    assessment_id: str
    workspace_id: str
    runtime: BrowserRuntimeName
    runtime_version: str
    target_url: str
    current_url: str | None = None
    pages_visited: int = Field(default=0, ge=0)
    forms_observed: int = Field(default=0, ge=0)
    network_observations: tuple[BrowserNetworkObservation, ...] = ()
    console_observations: tuple[BrowserConsoleObservation, ...] = ()
    screenshots: tuple[BrowserEvidenceArtifact, ...] = ()
    action_receipts: tuple[BrowserActionReceipt, ...] = ()
    endpoint_paths: tuple[str, ...] = ()
    source_hunt_correlation_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    report_sha256: str

    @field_validator("report_sha256")
    @classmethod
    def validate_report_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("browser report hash must be SHA-256")
        return value

    @classmethod
    def build(cls, **values: Any) -> BrowserIntelligenceReport:
        draft = dict(values)
        draft["report_sha256"] = "0" * 64
        provisional = cls.model_validate(draft)
        digest = sha256_json(provisional.model_dump(mode="json", exclude={"report_sha256"}))
        return provisional.model_copy(update={"report_sha256": digest})
