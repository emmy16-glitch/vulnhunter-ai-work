"""Bounded loopback-only Ollama/Qwen provider connector."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
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

_PROMPT_TEMPLATE_VERSION = "vulnhunter-qwen-proposal-v2"
_DEFAULT_MODEL = "qwen3.5:2b-q4_k_m"
_INFERENCE_SLOT = threading.BoundedSemaphore(1)


class OllamaProviderError(RuntimeError):
    """Fail-closed local-provider configuration or request error."""


class _OllamaProtocolError(OllamaProviderError):
    pass


class _StructuredModelOutput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    output_kind: ProviderOutputKind
    content: str = Field(min_length=1, max_length=200_000)


class OllamaProvider:
    """Use one approved local model for advisory structured output only.

    The connector exposes no tool schema, scanner, shell, database, approval, or
    publication capability. Endpoint checks do not load or download a model.
    """

    def __init__(
        self,
        *,
        endpoint: str = "http://127.0.0.1:11434",
        approved_models: tuple[str, ...] = (_DEFAULT_MODEL,),
        allow_non_loopback: bool = False,
        connection_timeout_seconds: float = 3.0,
        health_timeout_seconds: float = 3.0,
        context_tokens: int = 1_024,
        thinking_enabled: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.endpoint, self.endpoint_classification = self._validate_endpoint(
            endpoint, allow_non_loopback=allow_non_loopback
        )
        if not approved_models or any(not model.strip() for model in approved_models):
            raise OllamaProviderError("at least one explicit Ollama model must be approved")
        self.approved_models = tuple(dict.fromkeys(model.strip() for model in approved_models))
        self._approved_models_by_key = {
            self._model_key(model): model for model in self.approved_models
        }
        if len(self._approved_models_by_key) != len(self.approved_models):
            raise OllamaProviderError("approved Ollama models must be unique ignoring case")
        if not 0.1 <= connection_timeout_seconds <= 30:
            raise OllamaProviderError("Ollama connection timeout is outside the approved range")
        if not 0.1 <= health_timeout_seconds <= 10:
            raise OllamaProviderError("Ollama health timeout is outside the approved range")
        if not 256 <= context_tokens <= 8_192:
            raise OllamaProviderError("Ollama context limit is outside the approved range")
        self.connection_timeout_seconds = connection_timeout_seconds
        self.health_timeout_seconds = health_timeout_seconds
        self.context_tokens = context_tokens
        self.thinking_enabled = thinking_enabled
        self.transport = transport

    def health(self) -> ProviderHealth:
        """Check version and model inventory without loading or pulling a model."""

        try:
            version, model_digests = self._health_metadata()
        except (httpx.HTTPError, _OllamaProtocolError) as exc:
            return ProviderHealth(
                provider=ProviderKind.LOCAL_OLLAMA,
                configured=True,
                reachable=False,
                reason=f"Local Ollama health check failed safely: {type(exc).__name__}.",
                model=self.approved_models[0],
                endpoint_classification=self.endpoint_classification,
            )
        selected_key = next(
            (key for key in self._approved_models_by_key if key in model_digests),
            None,
        )
        if selected_key is None:
            return ProviderHealth(
                provider=ProviderKind.LOCAL_OLLAMA,
                configured=True,
                reachable=True,
                reason=(
                    "Ollama is reachable, but no approved model is installed; "
                    "auto-pull is disabled."
                ),
                model=self.approved_models[0],
                provider_version=version,
                endpoint_classification=self.endpoint_classification,
            )
        return ProviderHealth(
            provider=ProviderKind.LOCAL_OLLAMA,
            configured=True,
            reachable=True,
            reason="Ollama is reachable and the approved local model is installed.",
            model=model_digests[selected_key][0],
            model_digest=model_digests[selected_key][1],
            provider_version=version,
            endpoint_classification=self.endpoint_classification,
        )

    def invoke(
        self,
        invocation: ProviderInvocation,
        content: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProviderResponse:
        if invocation.provider != ProviderKind.LOCAL_OLLAMA:
            raise OllamaProviderError("Ollama invocation has the wrong provider identity")
        if self._model_key(invocation.model) not in self._approved_models_by_key:
            raise OllamaProviderError("Ollama model is not in the explicit allowlist")
        raw_content = content.encode("utf-8")
        if len(raw_content) > invocation.maximum_input_bytes:
            raise OllamaProviderError("Ollama prompt exceeds the configured byte limit")
        if len(raw_content) > invocation.maximum_input_tokens * 4:
            raise OllamaProviderError("Ollama prompt exceeds the conservative token limit")
        is_cancelled = cancelled or (lambda: False)
        requested_at = datetime.now(UTC)
        if is_cancelled():
            return self._abstain(
                invocation,
                raw_content,
                requested_at,
                "Local model request was cancelled before inference.",
                cancelled=True,
            )
        if not _INFERENCE_SLOT.acquire(timeout=self.connection_timeout_seconds):
            return self._abstain(
                invocation,
                raw_content,
                requested_at,
                "Local model inference capacity is busy.",
            )
        try:
            return self._invoke_locked(invocation, content, raw_content, requested_at, is_cancelled)
        finally:
            _INFERENCE_SLOT.release()

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
            version, model_digests = self._health_metadata()
            model_entry = model_digests.get(self._model_key(invocation.model))
            digest = model_entry[1] if model_entry is not None else None
            if model_entry is None:
                return self._abstain(
                    invocation,
                    raw_content,
                    requested_at,
                    "Approved local model is not installed; automatic model pull is disabled.",
                    provider_version=version,
                )
            prompt = self._prompt(content)
            prompt_bytes = prompt.encode("utf-8")
            if len(prompt_bytes) > invocation.maximum_input_bytes + 2_000:
                raise OllamaProviderError(
                    "Ollama templated prompt exceeds the configured byte limit"
                )
            outer = self._request_json(
                "POST",
                "/api/generate",
                maximum_bytes=min(400_000, invocation.maximum_output_bytes + 64_000),
                total_timeout_seconds=invocation.timeout_seconds,
                cancelled=is_cancelled,
                json_body={
                    "model": invocation.model,
                    "prompt": prompt,
                    "stream": False,
                    "think": self.thinking_enabled,
                    "format": {
                        "type": "object",
                        "properties": {
                            "output_kind": {
                                "type": "string",
                                "enum": [
                                    ProviderOutputKind.PROPOSAL.value,
                                    ProviderOutputKind.CANDIDATE_ANALYSIS.value,
                                    ProviderOutputKind.ABSTAIN.value,
                                ],
                            },
                            "content": {"type": "string"},
                        },
                        "required": ["output_kind", "content"],
                        "additionalProperties": False,
                    },
                    "options": {
                        "temperature": 0,
                        "num_ctx": self.context_tokens,
                        "num_predict": invocation.maximum_output_tokens,
                    },
                    "keep_alive": "0s",
                },
            )
            if is_cancelled():
                return self._abstain(
                    invocation,
                    raw_content,
                    requested_at,
                    "Local model request was cancelled.",
                    cancelled=True,
                    model_digest=digest,
                    provider_version=version,
                )
            response_text = outer.get("response")
            if not isinstance(response_text, str):
                raise _OllamaProtocolError("Ollama response omitted structured content")
            if len(response_text.encode("utf-8")) > invocation.maximum_output_bytes:
                raise _OllamaProtocolError("Ollama response exceeded the output byte limit")
            structured = _StructuredModelOutput.model_validate_json(response_text)
            if len(structured.content) > invocation.maximum_output_characters:
                raise _OllamaProtocolError("Ollama response exceeded the output character limit")
            output_bytes = structured.content.encode("utf-8")
            return ProviderResponse(
                invocation_id=invocation.invocation_id,
                provider=ProviderKind.LOCAL_OLLAMA,
                model=invocation.model,
                content=structured.content,
                output_sha256=hashlib.sha256(output_bytes).hexdigest(),
                output_kind=structured.output_kind,
                trusted=False,
                provenance=ProviderProvenance(
                    model_name=invocation.model,
                    model_digest=digest,
                    provider_version=version,
                    endpoint_classification=self.endpoint_classification,
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
                "Local model request timed out.",
                timed_out=True,
            )
        except (
            httpx.HTTPError,
            _OllamaProtocolError,
            ValidationError,
            json.JSONDecodeError,
        ) as exc:
            return self._abstain(
                invocation,
                raw_content,
                requested_at,
                f"Local model response was rejected safely: {type(exc).__name__}.",
            )

    def _health_metadata(self) -> tuple[str, dict[str, tuple[str, str | None]]]:
        version_payload = self._request_json(
            "GET",
            "/api/version",
            maximum_bytes=16_384,
            total_timeout_seconds=self.health_timeout_seconds,
        )
        tags_payload = self._request_json(
            "GET",
            "/api/tags",
            maximum_bytes=1_000_000,
            total_timeout_seconds=self.health_timeout_seconds,
        )
        version = version_payload.get("version")
        models = tags_payload.get("models")
        if not isinstance(version, str) or not isinstance(models, list):
            raise _OllamaProtocolError("Ollama health response is malformed")
        model_digests: dict[str, tuple[str, str | None]] = {}
        for item in models:
            if not isinstance(item, dict):
                continue
            name = item.get("name", item.get("model"))
            digest = item.get("digest")
            if isinstance(name, str):
                model_digests[self._model_key(name)] = (
                    name,
                    digest if isinstance(digest, str) else None,
                )
        return version[:128], model_digests

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
        with httpx.Client(
            base_url=self.endpoint,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        ) as client:
            with client.stream(method, path, json=json_body) as response:
                response.raise_for_status()
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if cancellation():
                        raise _OllamaProtocolError("Ollama response was cancelled")
                    raw.extend(chunk)
                    if len(raw) > maximum_bytes:
                        raise _OllamaProtocolError("Ollama HTTP response exceeded its byte limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _OllamaProtocolError("Ollama returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise _OllamaProtocolError("Ollama JSON response must be an object")
        return payload

    def _abstain(
        self,
        invocation: ProviderInvocation,
        raw_content: bytes,
        requested_at: datetime,
        safe_error: str,
        *,
        timed_out: bool = False,
        cancelled: bool = False,
        model_digest: str | None = None,
        provider_version: str | None = None,
    ) -> ProviderResponse:
        content = "ABSTAIN"
        output = content.encode("utf-8")
        return ProviderResponse(
            invocation_id=invocation.invocation_id,
            provider=ProviderKind.LOCAL_OLLAMA,
            model=invocation.model,
            content=content,
            output_sha256=hashlib.sha256(output).hexdigest(),
            output_kind=ProviderOutputKind.ABSTAIN,
            trusted=False,
            degraded=True,
            safe_error=safe_error,
            provenance=ProviderProvenance(
                model_name=invocation.model,
                model_digest=model_digest,
                provider_version=provider_version,
                endpoint_classification=self.endpoint_classification,
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
    def _model_key(value: str) -> str:
        """Normalize Ollama model identifiers without changing the requested tag.

        Ollama's CLI and registry may preserve quantization-tag casing in
        ``/api/tags`` while accepting a lowercase lookup name. Matching is
        therefore case-insensitive, but the configured/requested model string
        is still sent unchanged to the local API.
        """

        return value.strip().casefold()

    @staticmethod
    def _prompt(content: str) -> str:
        return (
            "You are an advisory cybersecurity analyst inside VulnHunter. "
            "Qwen proposes; VulnHunter enforces. Do not claim approval, authorization, "
            "scope expansion, execution, verification, severity confirmation, or publication. "
            "Do not request tools, shell access, scanners, credentials, or arbitrary files. "
            "Return exactly one JSON object with only output_kind and content. "
            "output_kind must be PROPOSAL, CANDIDATE_ANALYSIS, or ABSTAIN.\n\n"
            f"Bounded task context:\n{content}"
        )

    @staticmethod
    def _validate_endpoint(endpoint: str, *, allow_non_loopback: bool) -> tuple[str, str]:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.hostname is None
        ):
            raise OllamaProviderError("Ollama endpoint must be a plain HTTP origin")
        hostname = parsed.hostname.lower()
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname == "localhost"
        if not loopback and not allow_non_loopback:
            raise OllamaProviderError("non-loopback Ollama endpoints are denied by default")
        classification = "loopback" if loopback else "governed_non_loopback"
        return endpoint.rstrip("/"), classification
