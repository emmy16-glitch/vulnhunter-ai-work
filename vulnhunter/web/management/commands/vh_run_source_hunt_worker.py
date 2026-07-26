from __future__ import annotations

import os
import time
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.providers import GroqProvider, GroqProviderError
from vulnhunter.source_hunt import SourceHuntPolicy, SourceHuntStore
from vulnhunter.source_hunt.jobs import SourceHuntJobStore, process_next_source_hunt_job


def _approved_roots() -> tuple[Path, ...]:
    raw = os.environ.get("VULNHUNTER_SOURCE_HUNT_ROOTS", str(settings.BASE_DIR))
    roots = tuple(Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip())
    if not roots:
        raise CommandError("VULNHUNTER_SOURCE_HUNT_ROOTS has no approved root")
    return roots


def _job_store() -> SourceHuntJobStore:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_JOB_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-jobs"),
        )
    )
    return SourceHuntJobStore(root)


def _report_store() -> SourceHuntStore:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_REPORT_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-reports"),
        )
    )
    return SourceHuntStore(root)


def _policy() -> SourceHuntPolicy:
    return SourceHuntPolicy(
        approved_roots=_approved_roots(),
        model=settings.VULNHUNTER_GROQ_MODEL,
        maximum_prompt_bytes=min(settings.VULNHUNTER_GROQ_MAX_INPUT_BYTES, 100_000),
        maximum_output_tokens=min(settings.VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS, 4_000),
        timeout_seconds=min(settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS, 180),
    )


class Command(BaseCommand):
    help = "Run the separate, file-backed Groq Source Hunt worker."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--max-jobs", type=int, default=0)
        parser.add_argument("--poll-seconds", type=float, default=2.0)

    def handle(self, *args, **options) -> None:
        if not settings.VULNHUNTER_GROQ_ENABLED:
            raise CommandError("Groq is disabled by configuration.")
        maximum_jobs = int(options["max_jobs"])
        poll_seconds = float(options["poll_seconds"])
        if maximum_jobs < 0:
            raise CommandError("--max-jobs cannot be negative")
        if not 0.25 <= poll_seconds <= 60:
            raise CommandError("--poll-seconds must be between 0.25 and 60")
        try:
            provider = GroqProvider.from_key_file(
                Path(settings.VULNHUNTER_GROQ_API_KEY_FILE),
                approved_models=(
                    settings.VULNHUNTER_GROQ_MODEL,
                    settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
            )
        except GroqProviderError as exc:
            raise CommandError(str(exc)) from exc

        processed = 0
        while True:
            job = process_next_source_hunt_job(
                job_store=_job_store(),
                report_store=_report_store(),
                connector=provider,
                policy=_policy(),
            )
            if job is not None:
                processed += 1
                self.stdout.write(
                    f"{job.job_id}: {job.status.value}"
                    + (f" report={job.report_id}" if job.report_id else "")
                    + (f" error={job.safe_error}" if job.safe_error else "")
                )
            if options["once"] or (maximum_jobs and processed >= maximum_jobs):
                break
            if job is None:
                time.sleep(poll_seconds)

        self.stdout.write(self.style.SUCCESS(f"processed {processed} source-hunt job(s)"))
