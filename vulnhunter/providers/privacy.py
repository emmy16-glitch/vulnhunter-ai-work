"""Fail-closed privacy gate for local and remote model providers."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from vulnhunter.security import redact_text

_PRIVATE_IP = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:internal|local|lan|corp)\b", re.I)
_CODE_BLOCK = re.compile(r"```[\s\S]{300,}?```")


class PrivacyGateResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_for_remote: bool
    reason: str
    redacted_content: str


class PrivacyGate:
    def evaluate(
        self,
        content: str,
        *,
        contains_private_source: bool,
        contains_customer_data: bool,
    ) -> PrivacyGateResult:
        redacted = redact_text(content)
        redacted = _PRIVATE_IP.sub("[REDACTED_PRIVATE_IP]", redacted)
        redacted = _DOMAIN.sub("[REDACTED_PRIVATE_DOMAIN]", redacted)
        if contains_private_source or _CODE_BLOCK.search(content):
            return PrivacyGateResult(
                allowed_for_remote=False,
                reason="Private source code must remain with the local provider.",
                redacted_content=redacted,
            )
        if contains_customer_data:
            return PrivacyGateResult(
                allowed_for_remote=False,
                reason="Customer data must remain with the local provider.",
                redacted_content=redacted,
            )
        blocked_markers = (
            "[REDACTED_SECRET]",
            "[REDACTED_AUTHORIZATION]",
            "[REDACTED_COOKIE]",
            "[REDACTED_PRIVATE_KEY]",
        )
        if any(marker in redacted for marker in blocked_markers):
            return PrivacyGateResult(
                allowed_for_remote=False,
                reason="Sensitive values were detected and remote fallback was denied.",
                redacted_content=redacted,
            )
        return PrivacyGateResult(
            allowed_for_remote=True,
            reason="The request passed the remote-provider privacy gate.",
            redacted_content=redacted,
        )
