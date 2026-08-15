"""Compile parse-only Source Hunt fixtures into source-bound controlled ground truth."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.source_hunt.benchmark_v2 import (
    BenchmarkCorpusKind,
    SourceBenchmarkCorpus,
    SourceGroundTruthCase,
)
from vulnhunter.source_hunt.models import RepositorySnapshot
from vulnhunter.source_hunt.service import (
    RepositorySnapshotBuilder,
    SourceHuntError,
    SourceHuntPolicy,
)


class ControlledFixtureCaseDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    vulnerability_class: str = Field(min_length=2, max_length=80)
    path: str = Field(min_length=1, max_length=512)
    marker: str = Field(pattern=r"^VH-GT:[A-Z0-9._-]{2,64}$")
    expected_vulnerable: bool
    rationale: str = Field(min_length=8, max_length=2_000)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        normalized = PurePosixPath(value)
        if normalized.is_absolute() or ".." in normalized.parts:
            raise ValueError("controlled fixture paths must be repository-relative")
        return normalized.as_posix()


class ControlledFixtureDefinition(BaseModel):
    """Identity-neutral proposed truth; reviewer identity is supplied by governance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    corpus_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    cases: tuple[ControlledFixtureCaseDefinition, ...]

    @model_validator(mode="after")
    def validate_cases(self) -> ControlledFixtureDefinition:
        if not self.cases:
            raise ValueError("controlled fixture definition cannot be empty")
        case_ids = [item.case_id for item in self.cases]
        markers = [item.marker for item in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("controlled fixture case identifiers must be unique")
        if len(markers) != len(set(markers)):
            raise ValueError("controlled fixture markers must be unique")
        if not any(item.expected_vulnerable for item in self.cases):
            raise ValueError("controlled fixture requires at least one vulnerable case")
        if not any(not item.expected_vulnerable for item in self.cases):
            raise ValueError("controlled fixture requires at least one safe control case")
        return self


class CompiledControlledFixture(BaseModel):
    """Exact snapshot plus corpus proposal; still requires independent human review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot: RepositorySnapshot
    corpus: SourceBenchmarkCorpus
    marker_lines: tuple[tuple[str, int], ...]
    production_accuracy_claim_permitted: bool = False

    @model_validator(mode="after")
    def validate_binding(self) -> CompiledControlledFixture:
        if self.corpus.kind != BenchmarkCorpusKind.CONTROLLED_LAB:
            raise ValueError("compiled source fixtures must remain controlled-lab corpora")
        if self.production_accuracy_claim_permitted:
            raise ValueError("controlled fixture metrics cannot be production accuracy")
        if len(self.marker_lines) != len(self.corpus.cases):
            raise ValueError("controlled fixture marker count does not match ground truth")
        return self


class ControlledFixtureCompiler:
    """Resolve exact source markers without importing or executing fixture code."""

    def __init__(self, *, policy: SourceHuntPolicy) -> None:
        self.snapshot_builder = RepositorySnapshotBuilder(policy)

    def compile(
        self,
        fixture_root: Path,
        *,
        definition: ControlledFixtureDefinition,
    ) -> CompiledControlledFixture:
        root = fixture_root.expanduser().resolve(strict=True)
        preflight = self.snapshot_builder.build(root, revision="0" * 64)
        snapshot = self.snapshot_builder.build(root, revision=preflight.snapshot_sha256)
        if snapshot.snapshot_sha256 != preflight.snapshot_sha256:
            raise SourceHuntError("controlled fixture changed during compilation")

        file_index = {item.path: item for item in snapshot.files}
        cases: list[SourceGroundTruthCase] = []
        marker_lines: list[tuple[str, int]] = []
        for item in definition.cases:
            repository_file = file_index.get(item.path)
            if repository_file is None:
                raise ValueError(f"controlled fixture source is missing: {item.path}")
            path = root / item.path
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != repository_file.sha256:
                raise SourceHuntError("controlled fixture changed after snapshot creation")
            try:
                lines = raw.decode("utf-8").splitlines()
            except UnicodeDecodeError as exc:
                raise ValueError("controlled fixture source must be UTF-8") from exc
            pattern = re.compile(rf"#\s*{re.escape(item.marker)}(?:\s|$)")
            matches = [number for number, line in enumerate(lines, start=1) if pattern.search(line)]
            if len(matches) != 1:
                raise ValueError(
                    f"controlled fixture marker {item.marker!r} must occur exactly once"
                )
            line_number = matches[0]
            cases.append(
                SourceGroundTruthCase(
                    case_id=item.case_id,
                    vulnerability_class=item.vulnerability_class,
                    path=item.path,
                    line_start=line_number,
                    line_end=line_number,
                    expected_vulnerable=item.expected_vulnerable,
                )
            )
            marker_lines.append((item.marker, line_number))

        corpus = SourceBenchmarkCorpus.create(
            corpus_id=definition.corpus_id,
            kind=BenchmarkCorpusKind.CONTROLLED_LAB,
            cases=tuple(cases),
        )
        return CompiledControlledFixture(
            snapshot=snapshot,
            corpus=corpus,
            marker_lines=tuple(marker_lines),
        )
