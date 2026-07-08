"""Validated models representing approved laboratory targets."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ApprovedTarget(BaseModel):
    """An immutable target that passed VulnHunter scope validation."""

    model_config = ConfigDict(frozen=True)

    original_url: str
    normalized_url: str
    scheme: Literal["http", "https"]
    hostname: str
    port: int = Field(ge=1, le=65535)
    path: str
    resolved_addresses: tuple[str, ...]
