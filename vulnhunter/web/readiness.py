from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from django.db import DatabaseError, connection

from vulnhunter.agent import AgentStore, AgentStoreError


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    configuration: bool
    database: bool
    agent_store: bool

    @property
    def ready(self) -> bool:
        return self.configuration and self.database and self.agent_store

    def as_payload(self) -> dict[str, object]:
        return {
            "status": "ready" if self.ready else "unready",
            "checks": {
                "configuration": "ok" if self.configuration else "failed",
                "database": "ok" if self.database else "failed",
                "agent_store": "ok" if self.agent_store else "failed",
            },
        }


def database_is_ready() -> bool:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            return cursor.fetchone() == (1,)
    except DatabaseError:
        return False


def configuration_is_ready() -> bool:
    try:
        runtime_path = Path(settings.VULNHUNTER_SECURITY_TOOL_CONFIG).resolve(strict=True)
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, RuntimeError):
        return False
    return (
        isinstance(runtime, dict)
        and runtime.get("schema_version") == "1.0"
        and isinstance(runtime.get("execution_enabled"), bool)
    )


def agent_store_is_ready() -> bool:
    try:
        return AgentStore.open_existing(
            Path(settings.VULNHUNTER_AGENT_DATABASE)
        ).schema_version() == 1
    except AgentStoreError:
        return False


def deployment_readiness() -> ReadinessReport:
    """Evaluate the minimum local dependencies required to serve governed work."""

    return ReadinessReport(
        configuration=configuration_is_ready(),
        database=database_is_ready(),
        agent_store=agent_store_is_ready(),
    )
