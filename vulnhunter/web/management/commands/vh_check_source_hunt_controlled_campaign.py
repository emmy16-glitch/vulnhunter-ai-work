from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.source_hunt.benchmark_acceptance import (
    BenchmarkAcceptanceVerdict,
    SourceBenchmarkAcceptancePolicy,
)
from vulnhunter.source_hunt.controlled_corpus import (
    ControlledBenchmarkCampaignManifest,
    ControlledBenchmarkCampaignService,
    ControlledCorpusRelease,
)
from vulnhunter.source_hunt.models import SourceHuntReport


def _load_reports(directory: Path, manifest: ControlledBenchmarkCampaignManifest):
    return {
        release.draft.corpus.corpus_id: SourceHuntReport.model_validate_json(
            (directory / f"{release.draft.corpus.corpus_id}.json").read_text(encoding="utf-8")
        )
        for release in manifest.releases
    }


def _atomic_write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


class Command(BaseCommand):
    help = (
        "Evaluate exact pre-produced baseline and candidate Source Hunt reports using only "
        "independently reviewed controlled-lab corpus releases. No scan or model call is run."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument("--release-file", action="append", required=True)
        parser.add_argument("--policy-file", required=True)
        parser.add_argument("--baseline-report-dir", required=True)
        parser.add_argument("--candidate-report-dir", required=True)
        parser.add_argument("--baseline-engine-revision", required=True)
        parser.add_argument("--candidate-engine-revision", required=True)
        parser.add_argument("--output", required=True)

    def handle(self, *args, **options) -> None:
        try:
            releases = tuple(
                ControlledCorpusRelease.model_validate_json(Path(path).read_text(encoding="utf-8"))
                for path in options["release_file"]
            )
            policy = SourceBenchmarkAcceptancePolicy.model_validate_json(
                Path(options["policy_file"]).read_text(encoding="utf-8")
            )
            manifest = ControlledBenchmarkCampaignManifest.create(
                releases=releases,
                policy=policy,
                baseline_engine_revision=options["baseline_engine_revision"],
                candidate_engine_revision=options["candidate_engine_revision"],
            )
            evidence = ControlledBenchmarkCampaignService().evaluate(
                manifest=manifest,
                baseline_reports=_load_reports(Path(options["baseline_report_dir"]), manifest),
                candidate_reports=_load_reports(Path(options["candidate_report_dir"]), manifest),
            )
            _atomic_write(Path(options["output"]).expanduser(), evidence)
        except (OSError, ValueError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc

        acceptance = evidence.acceptance_bundle.acceptance
        if acceptance.verdict != BenchmarkAcceptanceVerdict.ACCEPTED:
            reasons = "; ".join(acceptance.reasons) or "acceptance policy rejected the candidate"
            raise CommandError(f"Controlled Source Hunt benchmark rejected: {reasons}")
        self.stdout.write(
            self.style.SUCCESS(
                f"accepted {manifest.candidate_engine_revision} with evidence "
                f"{evidence.evidence_sha256}"
            )
        )
