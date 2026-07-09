"""Validated contracts for controlled local benchmark workflows."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.ml.models import TrainingLabel


class BenchmarkPage(BaseModel):
    """One deterministic HTTP response served by the local benchmark."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(min_length=1, max_length=300)
    status_code: int = Field(default=200, ge=100, le=599)
    content_type: str = Field(default="text/html; charset=utf-8", min_length=1)
    headers: tuple[tuple[str, str], ...] = ()
    body: str = ""

    @model_validator(mode="after")
    def validate_path(self) -> BenchmarkPage:
        if not self.path.startswith("/"):
            raise ValueError("Benchmark page paths must begin with '/'.")
        if "?" in self.path or "#" in self.path:
            raise ValueError("Benchmark page paths cannot contain query or fragment data.")
        return self


class BenchmarkScenario(BaseModel):
    """One isolated benchmark site with a human-review suggestion."""

    model_config = ConfigDict(frozen=True)

    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,60}$")
    title: str = Field(min_length=1, max_length=160)
    suggested_label: TrainingLabel
    rationale: str = Field(min_length=1, max_length=1_000)
    pages: tuple[BenchmarkPage, ...]
    required_categories: tuple[str, ...]

    @model_validator(mode="after")
    def validate_scenario(self) -> BenchmarkScenario:
        if not self.pages:
            raise ValueError("A benchmark scenario must contain at least one page.")

        expected_root = f"/benchmark/{self.scenario_id}/"
        paths = tuple(page.path for page in self.pages)

        if expected_root not in paths:
            raise ValueError("A benchmark scenario must include its root page.")
        if len(paths) != len(set(paths)):
            raise ValueError("Benchmark page paths must be unique.")
        if any(not path.startswith(expected_root) for path in paths):
            raise ValueError("All benchmark pages must remain inside the scenario root.")
        if not self.required_categories:
            raise ValueError("required_categories must not be empty.")
        if len(self.required_categories) != len(set(self.required_categories)):
            raise ValueError("required_categories must be unique.")
        return self


class BenchmarkExpectation(BaseModel):
    """A benchmark suggestion that still requires explicit human confirmation."""

    model_config = ConfigDict(frozen=True)

    scenario_id: str
    observation_id: int = Field(ge=1)
    scan_id: int = Field(ge=1)
    fingerprint: str = Field(min_length=64, max_length=64)
    category: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    url: str
    suggested_label: TrainingLabel
    rationale: str


class BenchmarkScenarioResult(BaseModel):
    """Persisted result summary for one independent benchmark scan."""

    model_config = ConfigDict(frozen=True)

    scenario_id: str
    title: str
    scan_id: int = Field(ge=1)
    target_url: str
    suggested_label: TrainingLabel
    pages_visited: int = Field(ge=1)
    observations_count: int = Field(ge=1)


class BenchmarkManifest(BaseModel):
    """Integrity-protected record connecting benchmark truth to stored findings."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal[1] = 1
    run_id: str = Field(min_length=36, max_length=36)
    catalog_version: int = Field(ge=1)
    created_at: datetime
    database_path: str
    scenarios: tuple[BenchmarkScenarioResult, ...]
    expectations: tuple[BenchmarkExpectation, ...]

    @model_validator(mode="after")
    def validate_manifest(self) -> BenchmarkManifest:
        scenario_ids = tuple(item.scenario_id for item in self.scenarios)
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("Benchmark scenario IDs must be unique.")

        scan_ids = tuple(item.scan_id for item in self.scenarios)
        if len(scan_ids) != len(set(scan_ids)):
            raise ValueError("Benchmark scan IDs must be unique.")

        observation_ids = tuple(item.observation_id for item in self.expectations)
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("Benchmark observation IDs must be unique.")

        known_scenarios = set(scenario_ids)
        known_scan_ids = {item.scenario_id: item.scan_id for item in self.scenarios}
        for expectation in self.expectations:
            if expectation.scenario_id not in known_scenarios:
                raise ValueError("Expectation refers to an unknown scenario.")
            if expectation.scan_id != known_scan_ids[expectation.scenario_id]:
                raise ValueError("Expectation scan ID does not match its scenario.")

        if not self.expectations:
            raise ValueError("Benchmark manifest must contain expectations.")
        return self


class BenchmarkStatus(BaseModel):
    """Current human-review state of one benchmark manifest."""

    model_config = ConfigDict(frozen=True)

    total_expectations: int = Field(ge=0)
    pending: int = Field(ge=0)
    confirmed: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    needs_review: int = Field(ge=0)
    mismatched: int = Field(ge=0)
    complete: bool
