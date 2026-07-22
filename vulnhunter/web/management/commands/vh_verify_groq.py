from __future__ import annotations

import hashlib
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.providers import (
    GroqProvider,
    GroqProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
)


class Command(BaseCommand):
    help = "Run one bounded harmless Groq advisory inference through VulnHunter."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--model", default=settings.VULNHUNTER_GROQ_MODEL)
        parser.add_argument("--timeout", type=int, default=settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS)

    def handle(self, *args, **options) -> None:
        if not settings.VULNHUNTER_GROQ_ENABLED:
            raise CommandError("Groq is disabled by configuration.")
        model = str(options["model"]).strip()
        timeout = int(options["timeout"])
        if not 5 <= timeout <= 300:
            raise CommandError("timeout must be between 5 and 300 seconds")

        content = (
            "Return a candidate analysis whose content is exactly "
            "VULNHUNTER_GROQ_READY. Do not request tools, web search, code execution, "
            "MCP, approval, authorization, or publication."
        )
        raw = content.encode("utf-8")
        invocation = ProviderInvocation(
            invocation_id="groq-readiness",
            request_id="groq-readiness",
            provider=ProviderKind.GROQ_ADVISORY,
            model=model,
            capability=ProviderCapability.CLASSIFICATION,
            input_sha256=hashlib.sha256(raw).hexdigest(),
            maximum_input_characters=2_000,
            maximum_output_characters=1_000,
            maximum_input_bytes=4_000,
            maximum_output_bytes=4_000,
            maximum_input_tokens=1_000,
            maximum_output_tokens=1024,
            timeout_seconds=timeout,
        )
        try:
            provider = GroqProvider.from_key_file(
                Path(settings.VULNHUNTER_GROQ_API_KEY_FILE),
                approved_models=(
                    settings.VULNHUNTER_GROQ_MODEL,
                    settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
            )
            health = provider.health()
        except GroqProviderError as exc:
            raise CommandError(f"Groq configuration was rejected: {exc}") from exc
        if not health.reachable or health.model is None:
            raise CommandError(health.reason)
        if health.model != model:
            model = health.model
            invocation = invocation.model_copy(update={"model": model})

        response = provider.invoke(invocation, content)
        if response.output_kind == ProviderOutputKind.ABSTAIN:
            raise CommandError(response.safe_error or "Groq abstained during readiness test")
        if "VULNHUNTER_GROQ_READY" not in response.content:
            raise CommandError("Groq response passed schema validation but missed the marker")
        self.stdout.write(
            self.style.SUCCESS(
                "Groq verified: "
                f"model={response.model} output_kind={response.output_kind.value} "
                f"trusted={response.trusted}."
            )
        )
