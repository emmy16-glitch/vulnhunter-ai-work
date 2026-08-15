from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.conversation_service import interpret_request


class Command(BaseCommand):
    help = "Verify one configured high-reasoning LLM through the exact web conversation path."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--provider",
            choices=("auto", "groq", "huggingface"),
            default="auto",
            help=(
                "Provider to use. Auto resolves to the configured primary provider before the "
                "request and never enables failure-driven provider fallback."
            ),
        )
        parser.add_argument(
            "--reasoning",
            choices=("high",),
            default="high",
            help="Protected conversational readiness always uses high reasoning.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            dest="json_output",
            help="Emit a machine-readable readiness result.",
        )

    def handle(self, *args, **options) -> None:
        provider = str(options["provider"])
        reasoning = "high"
        marker = "VULNHUNTER_LLM_READY"
        interpreted = interpret_request(
            (
                "Answer this harmless VulnHunter readiness request. Your complete user-facing "
                f"answer must include the exact marker {marker}. Do not request tools, web "
                "search, credentials, target authorization, scanner execution, approval, or "
                "publication."
            ),
            available_profiles=("passive",),
            conversation_context=(
                ("user", "This workspace is performing a harmless LLM readiness check."),
            ),
            memory_summary="No durable user data is needed for this readiness check.",
            tool_context="No tools are available during this readiness check.",
            reasoning_effort=reasoning,
            provider_preference=provider,
        )

        answer = interpreted.assistant_copy or ""
        if not interpreted.model:
            raise CommandError(
                "The configured high-reasoning provider did not complete the web conversation "
                f"path. Detail: {interpreted.provider_detail}"
            )
        expected_provider = "groq" if provider == "auto" else provider
        if interpreted.provider != expected_provider:
            raise CommandError(
                f"The requested {expected_provider} provider was not used; got "
                f"{interpreted.provider}. Detail: {interpreted.provider_detail}"
            )
        if marker not in answer:
            raise CommandError(
                "The LLM completed the provider call but the web conversation answer missed "
                "the readiness marker."
            )
        if interpreted.reasoning_effort != "high":
            raise CommandError("The conversation path did not preserve high reasoning effort.")

        result = {
            "ready": True,
            "provider": interpreted.provider,
            "model": interpreted.model,
            "reasoning_effort": interpreted.reasoning_effort,
            "detail": interpreted.provider_detail,
        }
        if options["json_output"]:
            self.stdout.write(json.dumps(result, sort_keys=True))
            return
        self.stdout.write(
            self.style.SUCCESS(
                "LLM conversation verified: "
                f"provider={result['provider']} model={result['model']} "
                f"reasoning={result['reasoning_effort']}."
            )
        )
