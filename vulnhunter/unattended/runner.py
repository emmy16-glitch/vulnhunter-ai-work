"""Shell-free fixed command execution for approved unattended runs."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.exceptions import UnattendedExecutionError
from vulnhunter.security import redact_text
from vulnhunter.unattended.models import CommandEvidence, CommandId

_OUTPUT_LIMIT = 16_000

_COMMANDS: dict[CommandId, tuple[str, ...]] = {
    CommandId.GIT_STATUS: ("git", "status", "--short"),
    CommandId.GIT_DIFF_CHECK: ("git", "diff", "--check"),
    CommandId.RUFF_CHECK: (sys.executable, "-m", "ruff", "check", "."),
    CommandId.RUFF_FORMAT_CHECK: (sys.executable, "-m", "ruff", "format", "--check", "."),
    CommandId.COMPILE: (sys.executable, "-m", "compileall", "-q", "vulnhunter", "scripts"),
    CommandId.PYTEST: (sys.executable, "-m", "pytest", "-q"),
    CommandId.PROJECT_AUDIT: (sys.executable, "scripts/project_audit.py", "--strict"),
}


def command_registry() -> dict[CommandId, tuple[str, ...]]:
    """Return a copy of the immutable command registry."""
    return dict(_COMMANDS)


def execute_command(
    command_id: CommandId,
    *,
    repository: Path,
    run_id: str,
    actor_id: str,
    timeout_seconds: int,
) -> CommandEvidence:
    """Execute one fixed command without a shell or arbitrary arguments."""
    argv = _COMMANDS.get(command_id)
    if argv is None:
        raise UnattendedExecutionError(f"Unknown fixed command: {command_id}")
    started = datetime.now(UTC)
    started_monotonic = __import__("time").monotonic()
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "VIRTUAL_ENV": os.environ.get("VIRTUAL_ENV", ""),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1",
    }
    timed_out = False
    try:
        completed = subprocess.run(
            list(argv),
            cwd=repository,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
        return_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        return_code = 124
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + "\nCommand timed out."
    except OSError as exc:
        raise UnattendedExecutionError(f"Unable to execute {command_id.value}: {exc}") from exc

    completed_at = datetime.now(UTC)
    duration = __import__("time").monotonic() - started_monotonic
    provisional = CommandEvidence(
        run_id=run_id,
        command_id=command_id,
        actor_id=actor_id,
        started_at=started,
        completed_at=completed_at,
        duration_seconds=duration,
        return_code=return_code,
        stdout=redact_text(str(stdout))[-_OUTPUT_LIMIT:],
        stderr=redact_text(str(stderr))[-_OUTPUT_LIMIT:],
        timed_out=timed_out,
        evidence_sha256="0" * 64,
    )
    unsigned = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
    digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return provisional.model_copy(update={"evidence_sha256": digest})
