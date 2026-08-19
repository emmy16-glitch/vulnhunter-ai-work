"""Fail-closed authorization and scope policy for typed browser actions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.scope.models import ApprovedTarget
from vulnhunter.scope.validator import normalize_path

from .models import BrowserAction, BrowserActionType, BrowserMode, BrowserSession


class BrowserPolicyError(ValueError):
    """Raised when a browser action cannot be authorized safely."""


class BrowserActionLimits(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_actions: int = Field(default=80, ge=1, le=500)
    maximum_screenshots: int = Field(default=5, ge=0, le=20)
    maximum_consecutive_failures: int = Field(default=3, ge=1, le=10)
    maximum_repeated_action: int = Field(default=3, ge=1, le=10)
    maximum_evidence_bytes: int = Field(default=20_000_000, ge=1_024, le=100_000_000)


@dataclass(frozen=True)
class BrowserPolicy:
    """Authorization-aware policy used before every runtime call."""

    target: ApprovedTarget
    authorization_id: str
    mode: BrowserMode = BrowserMode.PASSIVE
    limits: BrowserActionLimits = BrowserActionLimits()
    allow_cross_origin: bool = False
    allow_evaluate: bool = False
    allow_credentials: bool = False

    def validate_action(
        self,
        action: BrowserAction,
        *,
        session: BrowserSession,
        now: datetime | None = None,
    ) -> BrowserAction:
        instant = (now or datetime.now(UTC)).astimezone(UTC)
        if session.authorization_id != self.authorization_id:
            raise BrowserPolicyError("browser session authorization does not match the policy")
        if session.state in {session.state.CANCELLED, session.state.EXPIRED, session.state.FAILED}:
            raise BrowserPolicyError("browser session is terminal")
        if instant >= session.expires_at:
            raise BrowserPolicyError("browser session has expired")
        if session.action_count >= self.limits.maximum_actions:
            raise BrowserPolicyError("browser action budget is exhausted")
        if action.action_type == BrowserActionType.TAKE_SCREENSHOT:
            if session.screenshot_count >= self.limits.maximum_screenshots:
                raise BrowserPolicyError("browser screenshot budget is exhausted")
        parameters = dict(action.parameters)
        self._validate_parameter_limits(action.action_type, parameters)
        if action.action_type == BrowserActionType.NAVIGATE:
            url = self._require_string(parameters, "url")
            self.validate_url(url)
        elif action.action_type in {
            BrowserActionType.CLICK,
            BrowserActionType.FILL,
            BrowserActionType.TYPE,
            BrowserActionType.SELECT_OPTION,
            BrowserActionType.GET_ATTRIBUTE,
        }:
            if not parameters.get("ref") and not parameters.get("selector"):
                raise BrowserPolicyError("element actions require a ref or selector")
            if (
                action.action_type
                in {
                    BrowserActionType.FILL,
                    BrowserActionType.TYPE,
                    BrowserActionType.SELECT_OPTION,
                }
                and self.mode != BrowserMode.CONTROLLED_INTERACTIVE
            ):
                raise BrowserPolicyError("form mutation requires controlled interactive policy")
            if action.action_type in {BrowserActionType.FILL, BrowserActionType.TYPE}:
                if not self.allow_credentials and self._looks_sensitive_field(parameters):
                    raise BrowserPolicyError(
                        "credential-like fields require an explicit credential policy"
                    )
        elif action.action_type == BrowserActionType.SEARCH_TEXT:
            self._require_string(parameters, "query")
        elif action.action_type == BrowserActionType.WAIT_FOR_TEXT:
            self._require_string(parameters, "text")
        elif action.action_type == BrowserActionType.WAIT:
            seconds = parameters.get("seconds", 0)
            if (
                isinstance(seconds, bool)
                or not isinstance(seconds, (int, float))
                or not 0 <= seconds <= 30
            ):
                raise BrowserPolicyError("wait seconds must be between 0 and 30")
        elif action.action_type == BrowserActionType.SCROLL:
            direction = str(parameters.get("direction", "down"))
            if direction not in {"top", "bottom", "up", "down", "left", "right"}:
                raise BrowserPolicyError("unsupported scroll direction")
        elif action.action_type == BrowserActionType.GET_ATTRIBUTE:
            attribute = self._require_string(parameters, "attribute")
            if len(attribute) > 100 or any(ord(c) < 32 for c in attribute):
                raise BrowserPolicyError("attribute name is invalid")
        elif action.action_type == BrowserActionType.COUNT:
            self._require_string(parameters, "selector")
        if action.action_type == BrowserActionType.GET_CURRENT_URL:
            return action
        if action.action_type.value == "browser_evaluate" or parameters.get("script") is not None:
            if not self.allow_evaluate:
                raise BrowserPolicyError("arbitrary browser evaluation is disabled")
        return action

    def validate_url(self, url: str) -> str:
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise BrowserPolicyError("browser URL is malformed") from exc
        if parsed.scheme not in {"http", "https"}:
            raise BrowserPolicyError("browser navigation only permits http and https")
        if parsed.username is not None or parsed.password is not None:
            raise BrowserPolicyError("browser navigation forbids URL credentials")
        if parsed.query or parsed.fragment:
            raise BrowserPolicyError(
                "browser action URLs may not contain query strings or fragments"
            )
        if parsed.hostname is None:
            raise BrowserPolicyError("browser navigation requires a hostname")
        hostname = parsed.hostname.rstrip(".").casefold()
        effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not self.allow_cross_origin:
            if hostname != self.target.hostname or parsed.scheme != self.target.scheme:
                raise BrowserPolicyError("browser navigation is outside the authorized origin")
            if effective_port != self.target.port:
                raise BrowserPolicyError("browser navigation is outside the authorized port")
            try:
                path = normalize_path(parsed.path)
            except Exception as exc:
                raise BrowserPolicyError("browser navigation path is invalid") from exc
            root = normalize_path(self.target.path).rstrip("/") or "/"
            current = path.rstrip("/") or "/"
            if root != "/" and current != root and not current.startswith(root + "/"):
                raise BrowserPolicyError("browser navigation is outside the authorized path")
        return url

    def _validate_parameter_limits(
        self, action_type: BrowserActionType, values: dict[str, Any]
    ) -> None:
        if len(values) > 12:
            raise BrowserPolicyError("browser action contains too many parameters")
        for key, value in values.items():
            if not isinstance(key, str) or len(key) > 80:
                raise BrowserPolicyError("browser action parameter name is invalid")
            if isinstance(value, str) and len(value) > 2_000:
                raise BrowserPolicyError("browser action parameter is too large")
            if isinstance(value, (list, tuple, dict)) and len(value) > 200:
                raise BrowserPolicyError("browser action parameter collection is too large")
        if action_type == BrowserActionType.TAKE_SCREENSHOT:
            width = values.get("width")
            height = values.get("height")
            for value in (width, height):
                if value is not None and (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 320 <= value <= 4_000
                ):
                    raise BrowserPolicyError("screenshot dimensions are outside the bounded range")

    @staticmethod
    def _require_string(values: dict[str, Any], name: str) -> str:
        value = values.get(name)
        if not isinstance(value, str) or not value.strip():
            raise BrowserPolicyError(f"browser action requires a non-empty {name}")
        return value.strip()

    @staticmethod
    def _looks_sensitive_field(values: dict[str, Any]) -> bool:
        text = " ".join(
            str(values.get(key, "")) for key in ("ref", "selector", "attribute")
        ).casefold()
        return any(
            token in text
            for token in ("password", "token", "secret", "api-key", "apikey", "authorization")
        )


__all__ = ["BrowserActionLimits", "BrowserPolicy", "BrowserPolicyError"]
