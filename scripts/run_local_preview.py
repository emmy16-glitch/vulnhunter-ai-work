#!/usr/bin/env python3
"""Start the development-only local preview on guest port 8002."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

_ALLOWED_PREVIEW_KEYS = {
    "VULNHUNTER_OLLAMA_ENDPOINT",
    "VULNHUNTER_OLLAMA_MODEL",
    "VULNHUNTER_OLLAMA_CONTEXT_TOKENS",
    "VULNHUNTER_OLLAMA_TIMEOUT_SECONDS",
    "VULNHUNTER_OLLAMA_INFERENCE_ENABLED",
    "VULNHUNTER_GROQ_ENABLED",
    "VULNHUNTER_GROQ_API_BASE",
    "VULNHUNTER_GROQ_API_KEY_FILE",
    "VULNHUNTER_GROQ_MODEL",
    "VULNHUNTER_GROQ_FALLBACK_MODEL",
    "VULNHUNTER_GROQ_TIMEOUT_SECONDS",
    "VULNHUNTER_GROQ_MAX_INPUT_BYTES",
    "VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS",
}


def _load_preview_environment() -> None:
    """Load allowlisted provider settings without reading credential contents."""

    root = Path.home() / ".config" / "vulnhunter"
    for config in (root / "groq.env",):
        if not config.is_file() or config.is_symlink():
            continue
        for raw_line in config.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key in _ALLOWED_PREVIEW_KEYS and value and "\x00" not in value:
                os.environ.setdefault(key, value)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    _load_preview_environment()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")
    os.environ.setdefault("VULNHUNTER_WEB_DEBUG", "true")
    os.environ.setdefault("VULNHUNTER_WEB_HTTPS", "false")
    os.environ.setdefault("VULNHUNTER_WEB_ALLOWED_HOSTS", "127.0.0.1,localhost,10.0.2.15")
    os.environ.setdefault(
        "VULNHUNTER_WEB_CSRF_TRUSTED_ORIGINS",
        "http://127.0.0.1:18002,http://127.0.0.1:8002,http://localhost:8002",
    )
    # Ephemeral and development-only: regenerated for each preview process and
    # never written to a file or used as a production default.
    os.environ.setdefault("VULNHUNTER_WEB_SECRET_KEY", secrets.token_urlsafe(48))
    os.environ.setdefault(
        "VULNHUNTER_AGENT_DATABASE",
        str(root / ".local" / "runtime" / "agent" / "agent.db"),
    )
    os.environ.setdefault(
        "VULNHUNTER_AUTHORIZATION_DATABASE",
        str(root / ".local" / "runtime" / "authorization" / "authorizations.db"),
    )
    os.environ.setdefault(
        "VULNHUNTER_GOVERNANCE_DATABASE",
        str(root / ".local" / "runtime" / "governance" / "governance.db"),
    )
    os.environ.setdefault("VULNHUNTER_OLLAMA_ENDPOINT", "http://127.0.0.1:11434")
    os.environ.setdefault("VULNHUNTER_OLLAMA_CONTEXT_TOKENS", "1024")
    os.environ.setdefault("VULNHUNTER_OLLAMA_TIMEOUT_SECONDS", "600")
    database = Path(os.environ["VULNHUNTER_AGENT_DATABASE"])
    if not database.is_file():
        print(
            "Agent runtime store is not initialized. Run: "
            "VULNHUNTER_WEB_DEBUG=true .venv/bin/python manage.py vh_init_agent_store",
            file=sys.stderr,
        )
        return 2

    from django.core.management import execute_from_command_line

    execute_from_command_line(["manage.py", "runserver", "0.0.0.0:8002", "--noreload"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
