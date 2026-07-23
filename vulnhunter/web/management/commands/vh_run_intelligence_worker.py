from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import ActivityStoreError, AppendOnlyActivityStore
from vulnhunter.intelligence import (
    GroqFindingReasoningLoop,
    IntelligenceAnalysisError,
    IntelligenceStore,
    IntelligenceStoreError,
)
from vulnhunter.learning import (
    ControlledLearningError,
    ControlledLearningService,
    ControlledMemoryStore,
    ControlledMemoryStoreError,
    safe_retrieve,
)
from vulnhunter.providers import GroqProvider, GroqProviderError


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise CommandError(f"{name} must be true or false")


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise CommandError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise CommandError(f"{name} must be between {minimum} and {maximum}")
    return value


def _record_activity(activity: AgentActivityService, **fields: object) -> None:
    """Project optional UI activity without affecting advisory persistence."""

    try:
        activity.record_transition(**fields)
    except (ActivityStoreError, OSError, TypeError, ValueError):
        return


class Command(BaseCommand):
    help = "Process bounded analyst-critic-synthesizer advisory finding analyses."

    def add_arguments(self, parser) -> None:
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--once", action="store_true", help="Process at most one item and exit.")
        mode.add_argument("--watch", action="store_true", help="Keep polling for queued analyses.")
        parser.add_argument("--poll-seconds", type=float, default=1.0)

    def handle(self, *args, **options) -> None:
        if not _env_bool("VULNHUNTER_INTELLIGENCE_ENABLED", False):
            self.stdout.write(
                self.style.WARNING(
                    "Advisory intelligence is disabled; deterministic verification remains active."
                )
            )
            return

        poll_seconds = float(options["poll_seconds"])
        if not 0.1 <= poll_seconds <= 60:
            raise CommandError("poll-seconds must be between 0.1 and 60")

        primary_model = os.environ.get(
            "VULNHUNTER_INTELLIGENCE_PRIMARY_MODEL", "openai/gpt-oss-20b"
        ).strip()
        deep_model = os.environ.get(
            "VULNHUNTER_INTELLIGENCE_DEEP_MODEL", "openai/gpt-oss-120b"
        ).strip()
        root = Path(
            os.environ.get(
                "VULNHUNTER_INTELLIGENCE_ROOT",
                str(Path(settings.BASE_DIR) / ".local" / "intelligence"),
            )
        )
        timeout_seconds = _env_int(
            "VULNHUNTER_INTELLIGENCE_TIMEOUT_SECONDS", 90, minimum=5, maximum=180
        )
        maximum_input_bytes = _env_int(
            "VULNHUNTER_INTELLIGENCE_MAX_INPUT_BYTES",
            64_000,
            minimum=4_000,
            maximum=100_000,
        )
        maximum_output_tokens = _env_int(
            "VULNHUNTER_INTELLIGENCE_MAX_OUTPUT_TOKENS",
            2_400,
            minimum=256,
            maximum=4_000,
        )
        maximum_attempts = _env_int(
            "VULNHUNTER_INTELLIGENCE_MAX_ATTEMPTS", 2, minimum=1, maximum=5
        )

        key_path = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser()
        try:
            provider = GroqProvider.from_key_file(
                key_path,
                approved_models=(primary_model, deep_model),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
            )
            store = IntelligenceStore(root)
            activity = AgentActivityService(
                AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))
            )
            loop = GroqFindingReasoningLoop(
                connector=provider,
                primary_model=primary_model,
                deep_model=deep_model,
                timeout_seconds=timeout_seconds,
                maximum_input_bytes=maximum_input_bytes,
                maximum_output_tokens=maximum_output_tokens,
            )
            learning_store = ControlledMemoryStore.from_environment()
            learning = ControlledLearningService(learning_store) if learning_store else None
        except (
            OSError,
            ValueError,
            GroqProviderError,
            IntelligenceAnalysisError,
            ControlledMemoryStoreError,
        ) as exc:
            raise CommandError(str(exc)) from exc

        watch = bool(options["watch"])
        try:
            while True:
                request = store.claim_next(maximum_attempts=maximum_attempts)
                if request is None:
                    if not watch:
                        self.stdout.write("No advisory finding analysis is pending.")
                        return
                    time.sleep(poll_seconds)
                    continue

                approved_memory = safe_retrieve(learning_store, request)
                _record_activity(
                    activity,
                    run_id=request.run_id,
                    timestamp=datetime.now(UTC),
                    event_type="evaluation_started",
                    summary=(
                        "Bounded advisory analysis started its analyst, critic, and "
                        "synthesizer stages."
                    ),
                    run_state="evaluating",
                    source="evaluator",
                    execution_state="running",
                    metadata={
                        "analysis_id": request.analysis_id,
                        "finding_id": request.finding_id,
                        "primary_model": primary_model,
                        "deep_model": deep_model,
                        "maximum_stages": 3,
                        "approved_memory_items": len(approved_memory),
                    },
                )
                try:
                    report = loop.run(request, approved_memory=approved_memory)
                    store.complete(report)
                except (OSError, ValueError, GroqProviderError, IntelligenceStoreError) as exc:
                    safe_error = f"{type(exc).__name__}: {exc}"[:500]
                    store.fail(
                        request.analysis_id,
                        safe_error,
                        maximum_attempts=maximum_attempts,
                    )
                    _record_activity(
                        activity,
                        run_id=request.run_id,
                        timestamp=datetime.now(UTC),
                        event_type="evaluation_completed",
                        summary=(
                            "Advisory analysis failed safely; deterministic verification "
                            "and human review remain authoritative."
                        ),
                        run_state="completed",
                        source="evaluator",
                        execution_state="failed",
                        error_code="advisory_analysis_failed",
                        error_message=safe_error,
                        metadata={
                            "analysis_id": request.analysis_id,
                            "finding_id": request.finding_id,
                            "advisory_only": True,
                            "trusted": False,
                        },
                    )
                    self.stderr.write(
                        self.style.WARNING(
                            f"Analysis {request.analysis_id} failed safely; "
                            "deterministic verification remains authoritative."
                        )
                    )
                else:
                    candidate_count = 0
                    if learning is not None:
                        try:
                            candidate_count = len(learning.propose_from_report(request, report))
                        except (
                            ControlledLearningError,
                            ControlledMemoryStoreError,
                            OSError,
                            ValueError,
                        ):
                            candidate_count = 0
                    final = report.final
                    _record_activity(
                        activity,
                        run_id=request.run_id,
                        timestamp=report.completed_at,
                        event_type="evaluation_completed",
                        summary=(
                            "Advisory reasoning completed after analyst, critic, and "
                            "synthesizer review."
                            if report.status.value == "completed"
                            else "Advisory reasoning abstained safely because the evidence "
                            "was insufficient or a provider stage was unavailable."
                        ),
                        run_state="completed",
                        source="evaluator",
                        execution_state="succeeded",
                        metadata={
                            "analysis_id": report.analysis_id,
                            "finding_id": report.finding_id,
                            "status": report.status.value,
                            "stage_count": len(report.stages),
                            "models": list(report.models),
                            "conclusion": final.conclusion if final else "abstain",
                            "summary": final.summary if final else report.safe_error or "ABSTAIN",
                            "missing_information": (
                                list(final.missing_information) if final else []
                            ),
                            "safe_verification_suggestions": (
                                list(final.safe_verification_suggestions) if final else []
                            ),
                            "remediation_options": (
                                list(final.remediation_options) if final else []
                            ),
                            "approved_memory_items": len(approved_memory),
                            "learning_candidates_created": candidate_count,
                            "trusted": False,
                            "advisory_only": True,
                        },
                    )
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
