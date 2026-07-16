"""Static-first, non-executing binary analysis models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class BinaryFormat(StrEnum):
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach_o"
    ZIP = "zip"
    DEX = "dex"
    UNKNOWN = "unknown"


class BinaryArchitecture(StrEnum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class StaticSignal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    signal_id: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...] = ()


class BinaryArtifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_path: str
    filename: str
    sha256: str
    size_bytes: int = Field(ge=0)
    format: BinaryFormat
    architecture: BinaryArchitecture = BinaryArchitecture.UNKNOWN
    entropy: float = Field(ge=0.0, le=8.0)
    printable_strings: tuple[str, ...] = ()
    signals: tuple[StaticSignal, ...] = ()
    analyzed_at: datetime = Field(default_factory=utc_now)
    executed: bool = False

    @field_validator("source_path")
    @classmethod
    def validate_source_path(cls, value: str) -> str:
        if not value or "\x00" in value:
            raise ValueError("source path must be a non-empty safe string")
        if Path(value).is_absolute():
            raise ValueError("stored source path must be repository-relative")
        return value


class BinaryAnalysisPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_bytes: int = Field(default=128 * 1024 * 1024, ge=1, le=2 * 1024 * 1024 * 1024)
    maximum_strings: int = Field(default=500, ge=0, le=10_000)
    minimum_string_length: int = Field(default=5, ge=3, le=128)
    permit_symlinks: bool = False
    execute_artifact: bool = False
