from __future__ import annotations

import time
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.intelligence import (
    GroqFindingReasoningLoop,
    IntelligenceAnalysisError,
    IntelligenceStore,
    IntelligenceStoreError,
)
from vulnhunter.providers import GroqProvider, GroqProviderError


class Command(BaseCommand):
    help = "Process bounded analyst-critic-synthesizer advisory finding analyses."

    def add_arguments(self, parser) -> None:
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--once", action="store_true", help="Process at most one item and exit.")
        mode.add_argument("--watch", action="store_true", help="Keep polling for queued analyses.")
        parser.add_argument("--poll-seconds", type=float, default=1.0)

    def handle(self, *args, **options) -> None:
        if not settings.VULNHUNTER_INTELLIGENCE_ENABLED:
            self.stdout.write(
                self.style.WARNING(
                    "Advisory intelligence is disabled; deterministic verification remains active."
                )
            )
            return

        poll_seconds = float(options["poll_seconds"])
        if not 0.1 <= poll_seconds <= 60:
            raise CommandError("poll-seconds must be between 0.1 and 60")

        key_path = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser()
        try:
            provider = GroqProvider.from_key_file(
                key_path,
                approved_models=(
                    settings.VULNHUNTER_INTELLIGENCE_PRIMARY_MODEL,
                    settings.VULNHUNTER_INTELLIGENCE_DEEP_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
            )
            store = IntelligenceStore(Path(settings.VULNHUNTER_INTELLIGENCE_ROOT))
            loop = GroqFindingReasoningLoop(
                connector=provider,
                primary_model=settings.VULNHUNTER_INTELLIGENCE_PRIMARY_MODEL,
                deep_model=settings.VULNHUNTER_INTELLIGENCE_DEEP_MODEL,
                timeout_seconds=settings.VULNHUNTER_INTELLIGENCE_TIMEOUT_SECONDS,
                maximum_input_bytes=settings.VULNHUNTER_INTELLIGENCE_MAX_INPUT_BYTES,
                maximum_output_tokens=settings.VULNHUNTER_INTELLIGENCE_MAX_OUTPUT_TOKENS,
            )
        except (OSError, ValueError, GroqProviderError, IntelligenceAnalysisError) as exc:
            raise CommandError(str(exc)) from exc

        watch = bool(options["watch"])
        try:
            while True:
                request = store.claim_next(
                    maximum_attempts=settings.VULNHUNTER_INTELLIGENCE_MAX_ATTEMPTS
                )
                if request is None:
                    if not watch:
                        self.stdout.write("No advisory finding analysis is pending.")
                        return
                    time.sleep(poll_seconds)
                    continue

                try:
                    report = loop.run(request)
                    store.complete(report)
                except (OSError, ValueError, GroqProviderError, IntelligenceStoreError) as exc:
                    store.fail(
                        request.analysis_id,
                        f"{type(exc).__name__}: {exc}",
                        maximum_attempts=settings.VULNHUNTER_INTELLIGENCE_MAX_ATTEMPTS,
                    )
                    self.stderr.write(
                        self.style.WARNING(
                            f"Analysis {request.analysis_id} failed safely; "
                            "deterministic verification remains authoritative."
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Analysis {request.analysis_id} finished as {report.status.value} "
                            f"after {len(report.stages)} bounded stage(s)."
                        )
                    )
                if not watch:
                    return
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("Advisory intelligence worker stopped."))
        except IntelligenceStoreError as exc:
            raise CommandError(str(exc)) from exc
