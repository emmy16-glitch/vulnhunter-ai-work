from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.conversation_service import interpret_request


class Command(BaseCommand):
    help = (
        "Verify one configured LLM through the exact bounded conversation path used by the web UI."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--provider",
            choices=("auto", "groq", "huggingface"),
            default="auto",
            help="Provider to require. Auto permits the configured fallback order.",
        )
        parser.add_argument(
            "--reasoning",
            choices=("low", "medium", "high"),
            default="low",
            help="Reasoning budget used for the harmless readiness answer.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            dest="json_output",
            help="Emit a machine-readable readiness result.",
        )

    def handle(self, *args, **options) -> None:
        provider = str(options["provider"])
        reasoning = str(options["reasoning"])
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
        if interpreted.provider == "deterministic":
            raise CommandError(
                "No configured remote LLM completed the web conversation path. "
                f"Detail: {interpreted.provider_detail}"
            )
        if provider != "auto" and interpreted.provider != provider:
            raise CommandError(
                f"The requested {provider} provider was not used; got {interpreted.provider}. "
                f"Detail: {interpreted.provider_detail}"
            )
        if marker not in answer:
            raise CommandError(
                "The LLM completed the provider call but the web conversation answer missed "
                "the readiness marker."
            )
        if not interpreted.model:
            raise CommandError("The LLM conversation response omitted its model identity.")

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
