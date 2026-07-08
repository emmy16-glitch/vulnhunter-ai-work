"""Validated models representing approved laboratory targets and URLs."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ApprovedTarget(BaseModel):
    """An immutable target that passed initial scope validation."""

    model_config = ConfigDict(frozen=True)

    original_url: str
    normalized_url: str
    scheme: Literal["http", "https"]
    hostname: str
    port: int = Field(ge=1, le=65535)
    path: str
    resolved_addresses: tuple[str, ...]


class ScopedUrl(BaseModel):
    """An immutable discovered URL proven to remain inside an approved target."""

    model_config = ConfigDict(frozen=True)

    url: str
    scheme: Literal["http", "https"]
    hostname: str
    port: int = Field(ge=1, le=65535)
    path: str
    query: str = ""
    resolved_addresses: tuple[str, ...]
