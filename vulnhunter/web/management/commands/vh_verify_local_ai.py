from __future__ import annotations

import hashlib

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.providers import (
    OllamaProvider,
    OllamaProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
)


class Command(BaseCommand):
    help = (
        "Run one bounded, harmless local Ollama inference through VulnHunter's "
        "governed provider adapter."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--timeout",
            type=int,
            default=settings.VULNHUNTER_OLLAMA_TIMEOUT_SECONDS,
            help="Total bounded inference timeout in seconds (10-600).",
        )

    def handle(self, *args, **options) -> None:
        timeout = int(options["timeout"])
        if not 10 <= timeout <= 600:
            raise CommandError("timeout must be between 10 and 600 seconds")

        content = (
            "Return a short candidate analysis whose content is exactly "
            "VULNHUNTER_LOCAL_MODEL_READY. Do not request tools or claim verification."
        )
        raw = content.encode("utf-8")
        invocation = ProviderInvocation(
            invocation_id="local-ai-readiness",
            request_id="local-ai-readiness",
            provider=ProviderKind.LOCAL_OLLAMA,
            model=settings.VULNHUNTER_OLLAMA_MODEL,
            capability=ProviderCapability.CLASSIFICATION,
            input_sha256=hashlib.sha256(raw).hexdigest(),
            maximum_input_characters=2_000,
            maximum_output_characters=1_000,
            maximum_input_bytes=4_000,
            maximum_output_bytes=4_000,
            maximum_input_tokens=1_000,
            maximum_output_tokens=64,
            timeout_seconds=timeout,
        )

        try:
            provider = OllamaProvider(
                endpoint=settings.VULNHUNTER_OLLAMA_ENDPOINT,
                approved_models=(settings.VULNHUNTER_OLLAMA_MODEL,),
                connection_timeout_seconds=5,
                health_timeout_seconds=5,
                context_tokens=settings.VULNHUNTER_OLLAMA_CONTEXT_TOKENS,
                thinking_enabled=False,
            )
            health = provider.health()
        except OllamaProviderError as exc:
            raise CommandError(f"Local AI configuration was rejected: {exc}") from exc

        if not health.reachable or health.model_digest is None:
            raise CommandError(health.reason)

        response = provider.invoke(invocation, content)
        if response.output_kind == ProviderOutputKind.ABSTAIN:
            raise CommandError(response.safe_error or "Local model abstained during readiness test")
        if "VULNHUNTER_LOCAL_MODEL_READY" not in response.content:
            raise CommandError(
                "Local model response passed schema validation but missed the marker"
            )

        self.stdout.write(
            self.style.SUCCESS(
                "Local AI verified: "
                f"model={health.model} digest={health.model_digest[:16]}... "
                f"output_kind={response.output_kind.value} trusted={response.trusted}."
            )
        )
