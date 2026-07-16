"""Repository coverage inventory records."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.actions.models import sha256_json


class CoverageState(StrEnum):
    ELIGIBLE = "eligible"
    EXCLUDED = "excluded"
    REVIEWED = "reviewed"
    PENDING = "pending"
    FAILED = "failed"
    CHANGED = "changed"


class CoverageExclusion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    reason: str = Field(min_length=3)


class CoverageItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str
    language: str
    component: str
    state: CoverageState = CoverageState.ELIGIBLE
    exclusion_reason: str | None = None


class CoverageInventory(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    root_sha256: str
    items: tuple[CoverageItem, ...]
    exclusions: tuple[CoverageExclusion, ...] = ()

    def metrics(self) -> dict[str, int]:
        return {
            "files_discovered": len(self.items),
            "files_eligible": sum(item.state == CoverageState.ELIGIBLE for item in self.items),
            "files_excluded": sum(item.state == CoverageState.EXCLUDED for item in self.items),
            "files_reviewed": sum(item.state == CoverageState.REVIEWED for item in self.items),
            "files_pending": sum(item.state == CoverageState.PENDING for item in self.items),
            "files_failed": sum(item.state == CoverageState.FAILED for item in self.items),
            "files_changed": sum(item.state == CoverageState.CHANGED for item in self.items),
        }

    def inventory_hash(self) -> str:
        return sha256_json(self.model_dump(mode="json"))
