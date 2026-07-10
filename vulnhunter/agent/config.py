"""Load and fingerprint the repository-controlled agent runtime configuration."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.agent.models import RuntimeConfig, sha256_json


class RuntimeConfigError(ValueError):
    """Raised when runtime configuration cannot be trusted."""


def load_runtime_config(
    path: Path | str = Path("config/agent_runtime/runtime.json"),
) -> RuntimeConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        return RuntimeConfig.model_validate(payload)
    except FileNotFoundError as exc:
        raise RuntimeConfigError(f"Runtime configuration is missing: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeConfigError(f"Runtime configuration is invalid JSON: {config_path}") from exc
    except ValidationError as exc:
        raise RuntimeConfigError(f"Runtime configuration is invalid: {exc}") from exc


def runtime_config_fingerprint(config: RuntimeConfig) -> str:
    return sha256_json(config.model_dump(mode="json"))
