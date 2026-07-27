from __future__ import annotations

import hashlib
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.providers import (
    HuggingFaceProvider,
    HuggingFaceProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
)


class Command(BaseCommand):
    help = "Run one bounded harmless Hugging Face advisory inference through VulnHunter."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--model", default=settings.VULNHUNTER_HUGGINGFACE_MODEL)
        parser.add_argument(
            "--timeout",
            type=int,
            default=settings.VULNHUNTER_HUGGINGFACE_TIMEOUT_SECONDS,
        )

    def handle(self, *args, **options) -> None:
        if not settings.VULNHUNTER_HUGGINGFACE_ENABLED:
            raise CommandError("Hugging Face is disabled by configuration.")
        model = str(options["model"]).strip()
        timeout = int(options["timeout"])
        if not 5 <= timeout <= 300:
            raise CommandError("timeout must be between 5 and 300 seconds")
        content = (
            "Return a candidate analysis whose content is exactly "
            "VULNHUNTER_HUGGINGFACE_READY. Do not request tools, credentials, private data, "
            "approval, authorization, execution, or publication."
        )
        raw = content.encode("utf-8")
        invocation = ProviderInvocation(
            invocation_id="huggingface-readiness",
            request_id="huggingface-readiness",
            provider=ProviderKind.HUGGINGFACE_ADVISORY,
            model=model,
            capability=ProviderCapability.CLASSIFICATION,
            input_sha256=hashlib.sha256(raw).hexdigest(),
            maximum_input_characters=2_000,
            maximum_output_characters=1_000,
            maximum_input_bytes=4_000,
            maximum_output_bytes=4_000,
            maximum_input_tokens=1_000,
            maximum_output_tokens=1_024,
            timeout_seconds=timeout,
            reasoning_effort="low",
        )
        try:
            provider = HuggingFaceProvider.from_token_file(
                Path(settings.VULNHUNTER_HUGGINGFACE_TOKEN_FILE),
                approved_models=(
                    settings.VULNHUNTER_HUGGINGFACE_MODEL,
                    settings.VULNHUNTER_HUGGINGFACE_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_HUGGINGFACE_API_BASE,
            )
            response = provider.invoke(invocation, content)
        except HuggingFaceProviderError as exc:
            raise CommandError(f"Hugging Face configuration was rejected: {exc}") from exc
        if response.output_kind == ProviderOutputKind.ABSTAIN:
            raise CommandError(
                response.safe_error or "Hugging Face abstained during readiness test"
            )
        if "VULNHUNTER_HUGGINGFACE_READY" not in response.content:
            raise CommandError(
                "Hugging Face response passed schema validation but missed the marker"
            )
        self.stdout.write(
            self.style.SUCCESS(
                "Hugging Face verified: "
                f"model={response.model} output_kind={response.output_kind.value} "
                f"trusted={response.trusted}."
            )
        )
