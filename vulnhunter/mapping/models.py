"""Models describing a bounded website-mapping operation."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.observations.models import Observation


class MapperPolicy(BaseModel):
    """Immutable limits for one breadth-first mapping operation."""

    model_config = ConfigDict(frozen=True)

    maximum_pages: int = Field(default=20, ge=1, le=500)
    maximum_depth: int = Field(default=2, ge=0, le=10)
    maximum_links_per_page: int = Field(default=200, ge=1, le=2_000)


class MappedPage(BaseModel):
    """Sanitised metadata for one successfully fetched page."""

    model_config = ConfigDict(frozen=True)

    url: str
    depth: int = Field(ge=0)
    status_code: int = Field(ge=100, le=599)
    content_type: str = ""
    response_bytes: int = Field(ge=0)
    elapsed_ms: float = Field(ge=0)
    title: str | None = None
    links_discovered: int = Field(default=0, ge=0)


class MappingResult(BaseModel):
    """Complete sanitised output of one bounded site map."""

    model_config = ConfigDict(frozen=True)

    target_url: str
    started_at: datetime
    completed_at: datetime
    pages: tuple[MappedPage, ...]
    observations: tuple[Observation, ...]
    discovered_urls: int = Field(ge=0)
    rejected_links: int = Field(ge=0)
