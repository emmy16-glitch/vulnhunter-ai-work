"""Bounded Groq advisory provider with deterministic privacy boundaries."""

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

_PROMPT_TEMPLATE_VERSION = "vulnhunter-groq-advisory-v2"
_DEFAULT_API_BASE = "https://api.groq.com/openai/v1"
_REMOTE_SLOT = threading.BoundedSemaphore(1)


class GroqProviderError(RuntimeError):
    """Fail-closed Groq configuration or protocol error."""


class _GroqProtocolError(GroqProviderError):
    pass


class _GroqHttpError(GroqProviderError):
    def __init__(self, status_code: int, safe_detail: str) -> None:
        self.status_code = status_code
        self.safe_detail = safe_detail
        super().__init__(f"Groq HTTP {status_code}: {safe_detail}")


class _StructuredModelOutput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    output_kind: ProviderOutputKind
    content: str = Field(min_length=1, max_length=40_000)


def load_groq_api_key_file(path: Path) -> str:
    """Load one owner-private key file without logging or exposing its value."""

    expanded = path.expanduser()
    if expanded.is_symlink():
        raise GroqProviderError("Groq API key file may not be a symbolic link")
    try:
        resolved = expanded.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise GroqProviderError("Groq API key file is unavailable") from exc
    if not resolved.is_file():
        raise GroqProviderError("Groq API key path must be a regular file")
    if metadata.st_uid != os.getuid():
        raise GroqProviderError("Groq API key file must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise GroqProviderError("Groq API key file permissions must be 0600 or stricter")
    try:
        value = resolved.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise GroqProviderError("Groq API key file could not be read safely") from exc
    if not value or len(value) > 512 or any(character.isspace() for character in value):
        raise GroqProviderError("Groq API key file contains an invalid value")
    return value


class GroqProvider:
    """Return bounded, non-authoritative advisory output only."""

    def __init__(
        self,
        *,
        api_key: str,
        approved_models: tuple[str, ...] = ("openai/gpt-oss-120b",),
        api_base: str = _DEFAULT_API_BASE,
        connection_timeout_seconds: float = 5.0,
        health_timeout_seconds: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key or len(api_key) > 512 or any(character.isspace() for character in api_key):
            raise GroqProviderError("Groq API key is invalid")
        self.api_key = api_key
        self.api_base = self._validate_api_base(api_base)
        if not approved_models or any(not model.strip() for model in approved_models):
            raise GroqProviderError("at least one explicit Groq model must be approved")
        self.approved_models = tuple(dict.fromkeys(model.strip() for model in approved_models))
        if not 0.1 <= connection_timeout_seconds <= 30:
            raise GroqProviderError("Groq connection timeout is outside the approved range")
        if not 0.1 <= health_timeout_seconds <= 30:
            raise GroqProviderError("Groq health timeout is outside the approved range")
        self.connection_timeout_seconds = connection_timeout_seconds
        self.health_timeout_seconds = health_timeout_seconds
        self.transport = transport

    @classmethod
    def from_key_file(cls, path: Path, **kwargs) -> GroqProvider:
        return cls(api_key=load_groq_api_key_file(path), **kwargs)

    def health(self) -> ProviderHealth:
        try:
            models = self._model_inventory()
        except (httpx.HTTPError, _GroqProtocolError, _GroqHttpError) as exc:
            return ProviderHealth(
                provider=ProviderKind.GROQ_ADVISORY,
                configured=True,
                reachable=False,
                reason=f"Groq health check failed safely: {type(exc).__name__}.",
                model=self.approved_models[0],
                endpoint_classification="remote_groqcloud",
            )
        selected = next((model for model in self.approved_models if model in models), None)
        if selected is None:
            return ProviderHealth(
                provider=ProviderKind.GROQ_ADVISORY,
                configured=True,
                reachable=True,
                reason="Groq is reachable, but no approved model is available.",
                model=self.approved_models[0],
                provider_version="groq-openai-compatible-v1",
                endpoint_classification="remote_groqcloud",
            )
        return ProviderHealth(
            provider=ProviderKind.GROQ_ADVISORY,
            configured=True,
            reachable=True,
            reason="Groq is reachable and an approved advisory model is available.",
            model=selected,
            provider_version="groq-openai-compatible-v1",
            endpoint_classification="remote_groqcloud",
        )

    def invoke(
        self,
        invocation: ProviderInvocation,
        content: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProviderResponse:
        if invocation.provider != ProviderKind.GROQ_ADVISORY:
            raise GroqProviderError("Groq invocation has the wrong provider identity")
        if invocation.model not in self.approved_models:
            raise GroqProviderError("Groq model is not in the explicit allowlist")
        raw_content = content.encode("utf-8")
        if len(raw_content) > invocation.maximum_input_bytes:
            raise GroqProviderError("Groq prompt exceeds the configured byte limit")
        if len(raw_content) > invocation.maximum_input_tokens * 4:
            raise GroqProviderError("Groq prompt exceeds the conservative token limit")

        requested_at = datetime.now(UTC)
        is_cancelled = cancelled or (lambda: False)
        if is_cancelled():
            return self._abstain(
                invocation,
                raw_content,
                requested_at,
                "Groq request was cancelled before transmission.",
                cancelled=True,
            )
        if not _REMOTE_SLOT.acquire(timeout=self.connection_timeout_seconds):
            return self._abstain(
                invocation,
                raw_content,
                requested_at,
                "Groq request capacity is busy.",
            )
        try:
            return self._invoke_locked(invocation, content, raw_content, requested_at, is_cancelled)
        finally:
            _REMOTE_SLOT.release()

    def __call__(self, invocation: ProviderInvocation, content: str) -> ProviderResponse:
        return self.invoke(invocation, content)

    def _invoke_locked(
        self,
        invocation: ProviderInvocation,
        content: str,
        raw_content: bytes,
        requested_at: datetime,
        is_cancelled: Callable[[], bool],
    ) -> ProviderResponse:
        try:
            payload = self._request_json(
                "POST",
                "/chat/completions",
                maximum_bytes=min(200_000, invocation.maximum_output_bytes + 64_000),
                total_timeout_seconds=invocation.timeout_seconds,
                cancelled=is_cancelled,
                json_body={
                    "model": invocation.model,
                    "messages": [
                        {"role": "system", "content": self._system_prompt()},
                        {"role": "user", "content": content},
                    ],
                    "temperature": 0.1,
                    "max_completion_tokens": invocation.maximum_output_tokens,
                    "reasoning_effort": "low",
                    "include_reasoning": False,
                    "response_format": {"type": "json_object"},
                    "stream": False,
                },
            )
            choices = payload.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                raise _GroqProtocolError("Groq response omitted choices")
            message = choices[0].get("message")
            if not isinstance(message, dict):
                raise _GroqProtocolError("Groq response omitted the assistant message")
            response_text = message.get("content")
            if not isinstance(response_text, str):
                raise _GroqProtocolError("Groq response omitted structured content")
            structured = _StructuredModelOutput.model_validate_json(response_text)
            output_bytes = structured.content.encode("utf-8")
            if len(output_bytes) > invocation.maximum_output_bytes:
                raise _GroqProtocolError("Groq response exceeded the output byte limit")
            return ProviderResponse(
                invocation_id=invocation.invocation_id,
                provider=ProviderKind.GROQ_ADVISORY,
                model=invocation.model,
                content=structured.content,
                output_sha256=hashlib.sha256(output_bytes).hexdigest(),
                output_kind=structured.output_kind,
                trusted=False,
                provenance=ProviderProvenance(
                    model_name=invocation.model,
                    provider_version=str(payload.get("system_fingerprint") or "groq"),
                    endpoint_classification="remote_groqcloud",
                    prompt_template_version=_PROMPT_TEMPLATE_VERSION,
                    request_timestamp=requested_at,
                    response_timestamp=datetime.now(UTC),
                    input_sha256=hashlib.sha256(raw_content).hexdigest(),
                    input_bytes=len(raw_content),
                    output_bytes=len(output_bytes),
                ),
            )
        except httpx.TimeoutException:
            return self._abstain(
                invocation,
                raw_content,
                requested_at,
                "Groq request timed out.",
                timed_out=True,
            )
        except _GroqHttpError as exc:
            reason = (
                "Groq request was rate-limited."
                if exc.status_code == 429
                else f"Groq request was rejected safely (HTTP {exc.status_code}): {exc.safe_detail}"
            )
            return self._abstain(invocation, raw_content, requested_at, reason)
        except (
            httpx.HTTPError,
            _GroqProtocolError,
            ValidationError,
            json.JSONDecodeError,
        ) as exc:
            return self._abstain(
                invocation,
                raw_content,
                requested_at,
                f"Groq response was rejected safely: {type(exc).__name__}.",
            )

    def _model_inventory(self) -> frozenset[str]:
        payload = self._request_json(
            "GET",
            "/models",
            maximum_bytes=2_000_000,
            total_timeout_seconds=self.health_timeout_seconds,
        )
        data = payload.get("data")
        if not isinstance(data, list):
            raise _GroqProtocolError("Groq model inventory is malformed")
        return frozenset(
            str(item["id"])
            for item in data
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        maximum_bytes: int,
        total_timeout_seconds: float,
        cancelled: Callable[[], bool] | None = None,
        json_body: dict[str, object] | None = None,
    ) -> dict[str, object]:
        cancellation = cancelled or (lambda: False)
        timeout = httpx.Timeout(
            connect=self.connection_timeout_seconds,
            read=total_timeout_seconds,
            write=self.connection_timeout_seconds,
            pool=self.connection_timeout_seconds,
        )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "VulnHunter/0.1 governed-advisory",
        }
        with httpx.Client(
            base_url=self.api_base,
            timeout=timeout,
            headers=headers,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        ) as client:
            with client.stream(method, path, json=json_body) as response:
                raw = bytearray()
                response_limit = maximum_bytes if response.is_success else min(maximum_bytes, 16_384)
                for chunk in response.iter_bytes():
                    if cancellation():
                        raise _GroqProtocolError("Groq response was cancelled")
                    raw.extend(chunk)
                    if len(raw) > response_limit:
                        if response.is_success:
                            raise _GroqProtocolError("Groq HTTP response exceeded its byte limit")
                        break
                if response.is_error:
                    raise _GroqHttpError(
                        response.status_code,
                        self._safe_http_error_detail(bytes(raw)),
                    )
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _GroqProtocolError("Groq returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise _GroqProtocolError("Groq JSON response must be an object")
        return payload

    def _safe_http_error_detail(self, raw: bytes) -> str:
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
        detail = " ".join(detail.split())[:500]
        if self.api_key:
            detail = detail.replace(self.api_key, "[REDACTED]")
        return detail or "remote request rejected"

    def _abstain(
        self,
        invocation: ProviderInvocation,
        raw_content: bytes,
        requested_at: datetime,
        safe_error: str,
        *,
        timed_out: bool = False,
        cancelled: bool = False,
    ) -> ProviderResponse:
        output = b"ABSTAIN"
        return ProviderResponse(
            invocation_id=invocation.invocation_id,
            provider=ProviderKind.GROQ_ADVISORY,
            model=invocation.model,
            content="ABSTAIN",
            output_sha256=hashlib.sha256(output).hexdigest(),
            output_kind=ProviderOutputKind.ABSTAIN,
            trusted=False,
            degraded=True,
            safe_error=safe_error,
            provenance=ProviderProvenance(
                model_name=invocation.model,
                provider_version="groq",
                endpoint_classification="remote_groqcloud",
                prompt_template_version=_PROMPT_TEMPLATE_VERSION,
                request_timestamp=requested_at,
                response_timestamp=datetime.now(UTC),
                input_sha256=hashlib.sha256(raw_content).hexdigest(),
                input_bytes=len(raw_content),
                output_bytes=len(output),
                timed_out=timed_out,
                cancelled=cancelled,
            ),
        )

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are an advisory cybersecurity analyst inside VulnHunter. "
            "VulnHunter controls authorization, scope, evidence, verification, severity, and "
            "publication. Never claim that you ran a tool, verified a finding, or approved an "
            "action. Do not request shell access, scanners, credentials, private files, web "
            "search, code execution, MCP, or connectors. Return exactly one JSON object with "
            "output_kind and content. output_kind must be PROPOSAL, CANDIDATE_ANALYSIS, or "
            "ABSTAIN."
        )

    @staticmethod
    def _validate_api_base(value: str) -> str:
        normalized = value.rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "api.groq.com"
            or parsed.port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/openai/v1"
            or parsed.query
            or parsed.fragment
        ):
            raise GroqProviderError("Groq API base must be https://api.groq.com/openai/v1")
        return normalized
