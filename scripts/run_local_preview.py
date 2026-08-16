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
    "VULNHUNTER_OLLAMA_ENABLED",
    "VULNHUNTER_OLLAMA_API_BASE",
    "VULNHUNTER_GROQ_ENABLED",
    "VULNHUNTER_GROQ_API_BASE",
    "VULNHUNTER_GROQ_API_KEY_FILE",
    "VULNHUNTER_GROQ_MODEL",
    "VULNHUNTER_GROQ_FALLBACK_MODEL",
    "VULNHUNTER_GROQ_TIMEOUT_SECONDS",
    "VULNHUNTER_GROQ_MAX_INPUT_BYTES",
    "VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS",
    "VULNHUNTER_GEMINI_ENABLED",
    "VULNHUNTER_GEMINI_API_BASE",
    "VULNHUNTER_GEMINI_API_KEY_FILE",
    "VULNHUNTER_GEMINI_MODEL",
    "VULNHUNTER_GEMINI_TIMEOUT_SECONDS",
}

_PREVIEW_CONFIG_FILES = (
    "providers.env",
    "groq.env",
    "gemini.env",
    "ollama.env",
)


def _owner_only_file(path: Path) -> bool:
    """Return True only for an ordinary owner-only credential file."""

    try:
        return path.is_file() and not path.is_symlink() and not (path.stat().st_mode & 0o077)
    except OSError:
        return False


def _load_preview_environment() -> None:
    """Load allowlisted provider settings without reading credential contents."""

    root = Path.home() / ".config" / "vulnhunter"
    for name in _PREVIEW_CONFIG_FILES:
        config = root / name
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


def _enable_provider_from_key_file(
    *,
    enabled_name: str,
    key_file_name: str,
    candidates: tuple[Path, ...],
) -> None:
    """Enable a provider when an owner-only local credential is already present."""

    configured = os.environ.get(key_file_name, "").strip()
    if configured:
        path = Path(configured).expanduser()
    else:
        path = next((candidate for candidate in candidates if _owner_only_file(candidate)), None)
        if path is None:
            return
        os.environ[key_file_name] = str(path)

    if _owner_only_file(path):
        os.environ.setdefault(enabled_name, "true")


def _configure_local_ai() -> None:
    """Discover secure local Groq/Gemini credentials; leave Ollama explicitly opt-in."""

    home = Path.home()
    config_root = home / ".config" / "vulnhunter"
    _enable_provider_from_key_file(
        enabled_name="VULNHUNTER_GROQ_ENABLED",
        key_file_name="VULNHUNTER_GROQ_API_KEY_FILE",
        candidates=(home / ".groq-api-key", config_root / "groq.key"),
    )
    _enable_provider_from_key_file(
        enabled_name="VULNHUNTER_GEMINI_ENABLED",
        key_file_name="VULNHUNTER_GEMINI_API_KEY_FILE",
        candidates=(config_root / "gemini.key", home / ".gemini-api-key"),
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    _load_preview_environment()
    _configure_local_ai()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")
    os.environ.setdefault("VULNHUNTER_WEB_DEBUG", "true")
    os.environ.setdefault("VULNHUNTER_WEB_HTTPS", "false")
    os.environ.setdefault("VULNHUNTER_WEB_ALLOWED_HOSTS", "127.0.0.1,localhost,10.0.2.15")
    os.environ.setdefault(
        "VULNHUNTER_WEB_CSRF_TRUSTED_ORIGINS",
        "http://127.0.0.1:18002,http://127.0.0.1:8002,http://localhost:8002",
    )
    # Ephemeral and development-only. Respect an explicitly configured secret or
    # owner-only secret file instead of creating a conflicting second credential.
    has_direct_secret = bool(os.environ.get("VULNHUNTER_WEB_SECRET_KEY", "").strip())
    has_secret_file = bool(os.environ.get("VULNHUNTER_WEB_SECRET_KEY_FILE", "").strip())
    if not has_direct_secret and not has_secret_file:
        os.environ["VULNHUNTER_WEB_SECRET_KEY"] = secrets.token_urlsafe(48)

    os.environ.setdefault(
        "VULNHUNTER_AGENT_DATABASE",
        str(root / ".local" / "runtime" / "agent" / "agent.db"),
    )
    os.environ.setdefault(
        "VULNHUNTER_AUTHORIZATION_DATABASE",
        str(root / ".local" / "runtime" / "authorization" / "authorizations.db"),
    )
    local_governance = root / "governance.db"
    governance_default = (
        local_governance
        if local_governance.is_file()
        else root / ".local" / "runtime" / "governance" / "governance.db"
    )
    os.environ.setdefault("VULNHUNTER_GOVERNANCE_DATABASE", str(governance_default))

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
