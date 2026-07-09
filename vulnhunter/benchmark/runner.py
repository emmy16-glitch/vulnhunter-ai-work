"""Orchestration for isolated, passive, loopback benchmark scans."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from vulnhunter.benchmark.catalog import CATALOG_VERSION, SCENARIOS
from vulnhunter.benchmark.manifest import save_manifest
from vulnhunter.benchmark.models import (
    BenchmarkExpectation,
    BenchmarkManifest,
    BenchmarkScenarioResult,
)
from vulnhunter.benchmark.server import BenchmarkServer
from vulnhunter.exceptions import BenchmarkError, VulnHunterError
from vulnhunter.mapping import MapperPolicy, SiteMapper
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.scanner import HttpClientPolicy, SafeHttpClient
from vulnhunter.scope import validate_target


async def run_benchmark_suite(
    database_path: Path,
    manifest_path: Path,
) -> BenchmarkManifest:
    """Run every catalog scenario as an independent passive loopback scan."""
    resolved_database = database_path.expanduser().resolve()
    resolved_manifest = manifest_path.expanduser().resolve()

    if resolved_manifest.exists():
        raise BenchmarkError(
            "Benchmark manifest already exists. Choose a new path or remove the old run explicitly."
        )

    repository = ScanRepository.from_path(resolved_database)
    repository.initialize()
    if repository.list_scans(limit=1):
        raise BenchmarkError(
            "Benchmark database must be empty so benchmark and real observations cannot mix."
        )

    scenario_results: list[BenchmarkScenarioResult] = []
    expectations: list[BenchmarkExpectation] = []

    with BenchmarkServer() as server:
        for scenario in SCENARIOS:
            target = validate_target(server.scenario_url(scenario.scenario_id))
            scan_id = repository.create_scan(target.normalized_url)

            try:
                async with SafeHttpClient(
                    target,
                    policy=HttpClientPolicy(
                        maximum_requests=25,
                        maximum_response_bytes=1 * 1024 * 1024,
                        minimum_request_delay_seconds=0,
                    ),
                ) as client:
                    mapper = SiteMapper(
                        target,
                        client,
                        policy=MapperPolicy(
                            maximum_pages=10,
                            maximum_depth=2,
                            maximum_links_per_page=50,
                        ),
                    )
                    result = await mapper.map()
                repository.complete_scan(scan_id, result)
            except Exception as exc:
                repository.fail_scan(scan_id, str(exc))
                if isinstance(exc, VulnHunterError):
                    raise
                raise BenchmarkError(
                    f"Benchmark scenario {scenario.scenario_id!r} failed safely."
                ) from exc

            observations = repository.list_observations(scan_id=scan_id, limit=1_000)
            observed_categories = {item.category for item in observations}
            missing_categories = set(scenario.required_categories) - observed_categories
            if missing_categories:
                raise BenchmarkError(
                    f"Scenario {scenario.scenario_id!r} did not produce required categories: "
                    + ", ".join(sorted(missing_categories))
                )

            scenario_results.append(
                BenchmarkScenarioResult(
                    scenario_id=scenario.scenario_id,
                    title=scenario.title,
                    scan_id=scan_id,
                    target_url=target.normalized_url,
                    suggested_label=scenario.suggested_label,
                    pages_visited=len(result.pages),
                    observations_count=len(observations),
                )
            )
            expectations.extend(
                BenchmarkExpectation(
                    scenario_id=scenario.scenario_id,
                    observation_id=observation.id,
                    scan_id=scan_id,
                    fingerprint=observation.fingerprint,
                    category=observation.category,
                    severity=observation.severity,
                    title=observation.title,
                    url=observation.url,
                    suggested_label=scenario.suggested_label,
                    rationale=scenario.rationale,
                )
                for observation in observations
            )

    manifest = BenchmarkManifest(
        run_id=str(uuid4()),
        catalog_version=CATALOG_VERSION,
        created_at=datetime.now(UTC),
        database_path=str(resolved_database),
        scenarios=tuple(scenario_results),
        expectations=tuple(sorted(expectations, key=lambda item: item.observation_id)),
    )
    save_manifest(manifest, resolved_manifest)
    return manifest
