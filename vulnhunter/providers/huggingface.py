"""Bounded Hugging Face Inference Providers client for optional advisory fallback."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnhunter.providers.models import (
    ProviderHealth,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
    ProviderProvenance,
    ProviderResponse,
)

_DEFAULT_API_BASE = "https://router.huggingface.co/v1"
_PROMPT_TEMPLATE_VERSION = "vulnhunter-huggingface-advisory-v1"
_REMOTE_SLOT = threading.BoundedSemaphore(4)


class HuggingFaceProviderError(RuntimeError):
    """Fail-closed Hugging Face configuration or protocol error."""


class _ProtocolError(HuggingFaceProviderError):
    pass


class _HttpError(HuggingFaceProviderError):
    def __init__(self, status_code: int, safe_detail: str) -> None:
        self.status_code = status_code
        self.safe_detail = safe_detail
        super().__init__(f"Hugging Face HTTP {status_code}: {safe_detail}")


class _StructuredModelOutput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    output_kind: ProviderOutputKind
    content: str = Field(min_length=1, max_length=40_000)


def load_huggingface_token_file(path: Path) -> str:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise HuggingFaceProviderError("Hugging Face token file may not be a symbolic link")
    try:
        resolved = expanded.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise HuggingFaceProviderError("Hugging Face token file is unavailable") from exc
    if not resolved.is_file():
        raise HuggingFaceProviderError("Hugging Face token path must be a regular file")
    if metadata.st_uid != os.getuid():
        raise HuggingFaceProviderError("Hugging Face token file must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise HuggingFaceProviderError(
            "Hugging Face token file permissions must be 0600 or stricter"
        )
    try:
        value = resolved.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise HuggingFaceProviderError("Hugging Face token file could not be read safely") from exc
    if not value or len(value) > 512 or any(character.isspace() for character in value):
        raise HuggingFaceProviderError("Hugging Face token file contains an invalid value")
    return value


class HuggingFaceProvider:
    """Call the OpenAI-compatible Hugging Face router without granting authority."""

    def __init__(
        self,
        *,
        token: str,
        approved_models: tuple[str, ...],
        api_base: str = _DEFAULT_API_BASE,
        connection_timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not token or len(token) > 512 or any(character.isspace() for character in token):
            raise HuggingFaceProviderError("Hugging Face token is invalid")
        if not approved_models or any(not item.strip() for item in approved_models):
            raise HuggingFaceProviderError("at least one Hugging Face model must be approved")
        if not 0.1 <= connection_timeout_seconds <= 30:
            raise HuggingFaceProviderError(
                "Hugging Face connection timeout is outside the approved range"
            )
        self.token = token
        self.api_base = self._validate_api_base(api_base)
        self.approved_models = tuple(dict.fromkeys(item.strip() for item in approved_models))
        self.connection_timeout_seconds = connection_timeout_seconds
        self.transport = transport

    @classmethod
    def from_token_file(cls, path: Path, **kwargs) -> HuggingFaceProvider:
        return cls(token=load_huggingface_token_file(path), **kwargs)

    def health(self) -> ProviderHealth:
        return ProviderHealth(
            provider=ProviderKind.HUGGINGFACE_ADVISORY,
            configured=True,
            reachable=True,
            reason="Hugging Face router is configured; live reachability is verified on inference.",
            model=self.approved_models[0],
            provider_version="huggingface-router-openai-v1",
            endpoint_classification="remote_huggingface_router",
        )

    def invoke(
        self,
        invocation: ProviderInvocation,
        content: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProviderResponse:
        if invocation.provider != ProviderKind.HUGGINGFACE_ADVISORY:
            raise HuggingFaceProviderError(
                "Hugging Face invocation has the wrong provider identity"
            )
        if invocation.model not in self.approved_models:
            raise HuggingFaceProviderError("Hugging Face model is not in the explicit allowlist")
        raw = content.encode("utf-8")
        if len(raw) > invocation.maximum_input_bytes:
            raise HuggingFaceProviderError("Hugging Face prompt exceeds the configured byte limit")
        if len(raw) > invocation.maximum_input_tokens * 4:
            raise HuggingFaceProviderError(
                "Hugging Face prompt exceeds the conservative token limit"
            )
        requested_at = datetime.now(UTC)
        is_cancelled = cancelled or (lambda: False)
        if is_cancelled():
            return self._abstain(
                invocation, raw, requested_at, "Hugging Face request was cancelled.", cancelled=True
            )
        if not _REMOTE_SLOT.acquire(timeout=self.connection_timeout_seconds):
            return self._abstain(
                invocation, raw, requested_at, "Hugging Face request capacity is busy."
            )
        try:
            return self._invoke_locked(invocation, content, raw, requested_at, is_cancelled)
        finally:
            _REMOTE_SLOT.release()

    def _invoke_locked(
        self,
        invocation: ProviderInvocation,
        content: str,
        raw: bytes,
        requested_at: datetime,
        cancelled: Callable[[], bool],
    ) -> ProviderResponse:
        try:
            payload = self._request_json(
                invocation=invocation,
                content=content,
                cancelled=cancelled,
            )
            choices = payload.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                raise _ProtocolError("Hugging Face response omitted choices")
            message = choices[0].get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), str):
                raise _ProtocolError("Hugging Face response omitted structured content")
            structured = _StructuredModelOutput.model_validate_json(message["content"])
            output = structured.content.encode("utf-8")
            if len(output) > invocation.maximum_output_bytes:
                raise _ProtocolError("Hugging Face response exceeded the output byte limit")
            return ProviderResponse(
                invocation_id=invocation.invocation_id,
                provider=ProviderKind.HUGGINGFACE_ADVISORY,
                model=invocation.model,
                content=structured.content,
                output_sha256=hashlib.sha256(output).hexdigest(),
                output_kind=structured.output_kind,
                trusted=False,
                provenance=ProviderProvenance(
                    model_name=invocation.model,
                    provider_version=str(payload.get("system_fingerprint") or "huggingface-router"),
                    endpoint_classification="remote_huggingface_router",
                    prompt_template_version=_PROMPT_TEMPLATE_VERSION,
                    request_timestamp=requested_at,
                    response_timestamp=datetime.now(UTC),
                    input_sha256=hashlib.sha256(raw).hexdigest(),
                    input_bytes=len(raw),
                    output_bytes=len(output),
                ),
            )
        except httpx.TimeoutException:
            return self._abstain(
                invocation, raw, requested_at, "Hugging Face request timed out.", timed_out=True
            )
        except _HttpError as exc:
            reason = (
                "Hugging Face request was rate-limited."
                if exc.status_code == 429
                else (
                    f"Hugging Face request was rejected safely (HTTP {exc.status_code}): "
                    f"{exc.safe_detail}"
                )
            )
            return self._abstain(invocation, raw, requested_at, reason)
        except (httpx.HTTPError, _ProtocolError, ValidationError, json.JSONDecodeError) as exc:
            return self._abstain(
                invocation,
                raw,
                requested_at,
                f"Hugging Face response was rejected safely: {type(exc).__name__}.",
            )

    def _request_json(
        self,
        *,
        invocation: ProviderInvocation,
        content: str,
        cancelled: Callable[[], bool],
    ) -> dict[str, object]:
        timeout = httpx.Timeout(
            connect=self.connection_timeout_seconds,
            read=invocation.timeout_seconds,
            write=self.connection_timeout_seconds,
            pool=self.connection_timeout_seconds,
        )
        body = {
            "model": invocation.model,
            "messages": [
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": content},
            ],
            "temperature": 0.1,
            "max_tokens": invocation.maximum_output_tokens,
            "reasoning_effort": invocation.reasoning_effort,
            "response_format": {"type": "json_object"},
            "stream": False,
        }
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": "VulnHunter/0.1 governed-advisory",
        }
        with httpx.Client(
            base_url=self.api_base,
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        ) as client:
            with client.stream("POST", "/chat/completions", json=body) as response:
                raw = bytearray()
                limit = min(200_000, invocation.maximum_output_bytes + 64_000)
                for chunk in response.iter_bytes():
                    if cancelled():
                        raise _ProtocolError("Hugging Face response was cancelled")
                    raw.extend(chunk)
                    if len(raw) > limit:
                        raise _ProtocolError("Hugging Face HTTP response exceeded its byte limit")
                if response.is_error:
                    raise _HttpError(response.status_code, self._safe_error(bytes(raw)))
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _ProtocolError("Hugging Face returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise _ProtocolError("Hugging Face JSON response must be an object")
        return payload

    def _safe_error(self, raw: bytes) -> str:
        detail = "remote request rejected"
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict) and isinstance(error.get("message"), str):
                detail = error["message"]
            elif isinstance(error, str):
                detail = error
        return " ".join(detail.replace(self.token, "[REDACTED]").split())[:500]

    def _abstain(
        self,
        invocation: ProviderInvocation,
        raw: bytes,
        requested_at: datetime,
        safe_error: str,
        *,
        timed_out: bool = False,
        cancelled: bool = False,
    ) -> ProviderResponse:
        output = b"ABSTAIN"
        return ProviderResponse(
            invocation_id=invocation.invocation_id,
            provider=ProviderKind.HUGGINGFACE_ADVISORY,
            model=invocation.model,
            content="ABSTAIN",
            output_sha256=hashlib.sha256(output).hexdigest(),
            output_kind=ProviderOutputKind.ABSTAIN,
            trusted=False,
            degraded=True,
            safe_error=safe_error,
            provenance=ProviderProvenance(
                model_name=invocation.model,
                provider_version="huggingface-router",
                endpoint_classification="remote_huggingface_router",
                prompt_template_version=_PROMPT_TEMPLATE_VERSION,
                request_timestamp=requested_at,
                response_timestamp=datetime.now(UTC),
                input_sha256=hashlib.sha256(raw).hexdigest(),
                input_bytes=len(raw),
                output_bytes=len(output),
                timed_out=timed_out,
                cancelled=cancelled,
            ),
        )

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are an advisory assistant inside VulnHunter. Return exactly one JSON object with "
            "output_kind and content. Never claim authority over authorization, scope, scanner "
            "execution, finding verification, severity, publication, or human approval."
        )

    @staticmethod
    def _validate_api_base(value: str) -> str:
        normalized = value.rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "router.huggingface.co"
            or parsed.port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/v1"
            or parsed.query
            or parsed.fragment
        ):
            raise HuggingFaceProviderError(
                "Hugging Face API base must be https://router.huggingface.co/v1"
            )
        return normalized
