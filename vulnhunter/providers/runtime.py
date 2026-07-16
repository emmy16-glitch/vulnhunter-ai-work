"""Provider runtime with explicit activation, budgets, and schema-safe outputs."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from typing import Protocol

from vulnhunter.providers.models import (
    ProviderHealth,
    ProviderInvocation,
    ProviderKind,
    ProviderRequest,
    ProviderResponse,
)
from vulnhunter.providers.registry import ProviderRegistry


class ProviderRuntimeError(RuntimeError):
    pass


class StructuredProviderConnector(Protocol):
    def invoke(
        self,
        invocation: ProviderInvocation,
        content: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProviderResponse: ...


ProviderConnector = (
    Callable[[ProviderInvocation, str], str | ProviderResponse] | StructuredProviderConnector
)
HealthConnector = Callable[[], ProviderHealth]


class ProviderRuntime:
    """Execute only explicitly registered provider connectors.

    Connectors are injected at the composition root so this module never reads,
    stores, or guesses API credentials.
    """

    def __init__(
        self,
        *,
        registry: ProviderRegistry,
        connectors: dict[ProviderKind, ProviderConnector] | None = None,
        health_connectors: dict[ProviderKind, HealthConnector] | None = None,
    ) -> None:
        self.registry = registry
        self.connectors = connectors or {}
        self.health_connectors = health_connectors or {}

    def health(self, provider: ProviderKind) -> ProviderHealth:
        connector = self.health_connectors.get(provider)
        if connector is None:
            return ProviderHealth(
                provider=provider,
                configured=False,
                reachable=False,
                reason="Provider connector is not configured or activated.",
            )
        result = connector()
        if result.provider != provider:
            raise ProviderRuntimeError("provider health connector returned the wrong identity")
        return result

    def invoke(
        self,
        request: ProviderRequest,
        invocation: ProviderInvocation,
        *,
        cancellation_event: threading.Event | None = None,
    ) -> ProviderResponse:
        if invocation.request_id != request.request_id:
            raise ProviderRuntimeError("provider invocation is bound to another request")
        route = self.registry.route(request)
        if not route.allowed or route.provider != invocation.provider:
            raise ProviderRuntimeError("provider route is denied or does not match the invocation")
        content = route.redacted_content
        if content is None:
            raise ProviderRuntimeError("provider route did not produce safe content")
        if len(content) > invocation.maximum_input_characters:
            raise ProviderRuntimeError("provider input exceeds the configured limit")
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > invocation.maximum_input_bytes:
            raise ProviderRuntimeError("provider input exceeds the configured byte limit")
        expected_input_sha256 = hashlib.sha256(content_bytes).hexdigest()
        if invocation.input_sha256 != expected_input_sha256:
            raise ProviderRuntimeError("provider invocation input binding is invalid")
        connector = self.connectors.get(invocation.provider)
        if connector is None:
            raise ProviderRuntimeError("provider connector is not activated")
        if hasattr(connector, "invoke"):
            output = connector.invoke(
                invocation,
                content,
                cancelled=(cancellation_event.is_set if cancellation_event else None),
            )
        else:
            output = connector(invocation, content)
        if isinstance(output, ProviderResponse):
            if (
                output.invocation_id != invocation.invocation_id
                or output.provider != invocation.provider
                or output.model != invocation.model
                or output.trusted
            ):
                raise ProviderRuntimeError("provider connector response binding is invalid")
            encoded = output.content.encode("utf-8")
            if (
                len(output.content) > invocation.maximum_output_characters
                or len(encoded) > invocation.maximum_output_bytes
                or hashlib.sha256(encoded).hexdigest() != output.output_sha256
            ):
                raise ProviderRuntimeError("provider connector response failed integrity limits")
            return output
        if not isinstance(output, str):
            raise ProviderRuntimeError("provider connector returned an invalid output type")
        if len(output) > invocation.maximum_output_characters:
            raise ProviderRuntimeError("provider output exceeds the configured limit")
        if len(output.encode("utf-8")) > invocation.maximum_output_bytes:
            raise ProviderRuntimeError("provider output exceeds the configured byte limit")
        return ProviderResponse(
            invocation_id=invocation.invocation_id,
            provider=invocation.provider,
            model=invocation.model,
            content=output,
            output_sha256=hashlib.sha256(output.encode()).hexdigest(),
            trusted=False,
        )
