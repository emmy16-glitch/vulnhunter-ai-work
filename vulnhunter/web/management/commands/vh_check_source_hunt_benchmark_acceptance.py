from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.source_hunt.benchmark_acceptance import (
    BenchmarkAcceptanceVerdict,
    SourceBenchmarkAcceptanceBundle,
    SourceBenchmarkAcceptanceEvaluator,
    SourceBenchmarkAcceptancePolicy,
    SourceBenchmarkCampaignRunner,
    SourceBenchmarkSuite,
)
from vulnhunter.source_hunt.models import SourceHuntReport


def _load_reports(directory: Path, suite: SourceBenchmarkSuite) -> dict[str, SourceHuntReport]:
    reports: dict[str, SourceHuntReport] = {}
    for entry in suite.entries:
        path = directory / f"{entry.corpus.corpus_id}.json"
        reports[entry.corpus.corpus_id] = SourceHuntReport.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    return reports


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


class Command(BaseCommand):
    help = (
        "Compare baseline and candidate Source Hunt reports against one immutable controlled "
        "benchmark suite. This command performs no scan, model call or network request."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument("--suite-file", required=True)
        parser.add_argument("--policy-file", required=True)
        parser.add_argument("--baseline-report-dir", required=True)
        parser.add_argument("--candidate-report-dir", required=True)
        parser.add_argument("--baseline-engine-revision", required=True)
        parser.add_argument("--candidate-engine-revision", required=True)
        parser.add_argument("--output", required=True)

    def handle(self, *args, **options) -> None:
        try:
            suite = SourceBenchmarkSuite.model_validate_json(
                Path(options["suite_file"]).read_text(encoding="utf-8")
            )
            policy = SourceBenchmarkAcceptancePolicy.model_validate_json(
                Path(options["policy_file"]).read_text(encoding="utf-8")
            )
            runner = SourceBenchmarkCampaignRunner()
            baseline = runner.run(
                label="baseline",
                engine_revision=options["baseline_engine_revision"],
                suite=suite,
                reports=_load_reports(Path(options["baseline_report_dir"]), suite),
            )
            candidate = runner.run(
                label="candidate",
                engine_revision=options["candidate_engine_revision"],
                suite=suite,
                reports=_load_reports(Path(options["candidate_report_dir"]), suite),
            )
            acceptance = SourceBenchmarkAcceptanceEvaluator().evaluate(
                policy=policy,
                baseline=baseline,
                candidate=candidate,
            )
            bundle = SourceBenchmarkAcceptanceBundle.create(
                baseline=baseline,
                candidate=candidate,
                acceptance=acceptance,
            )
            output = Path(options["output"]).expanduser()
            _atomic_write(
                output,
                json.dumps(bundle.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
            )
        except (OSError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        if acceptance.verdict != BenchmarkAcceptanceVerdict.ACCEPTED:
            reasons = "; ".join(acceptance.reasons) or "acceptance policy rejected the candidate"
            raise CommandError(f"Source Hunt benchmark rejected: {reasons}")
        self.stdout.write(
            self.style.SUCCESS(
                f"accepted {candidate.engine_revision} with evidence {bundle.bundle_sha256}"
            )
        )
