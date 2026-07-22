from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from django import template

register = template.Library()


@register.simple_tag
def remote_nuclei_status() -> dict[str, object]:
    """Report configured state without opening SSH or contacting a target."""

    configured_path = os.environ.get("VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY", "").strip()
    if not configured_path:
        return {
            "configured": False,
            "enabled": False,
            "state": "not configured",
            "detail": "No owner-private remote worker policy is selected for this runtime.",
            "worker_id": "—",
        }
    path = Path(configured_path).expanduser()
    if path.is_symlink():
        return {
            "configured": True,
            "enabled": False,
            "state": "invalid",
            "detail": "The selected remote worker policy is a symbolic link.",
            "worker_id": "—",
        }
    try:
        metadata = path.stat()
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "configured": True,
            "enabled": False,
            "state": "unavailable",
            "detail": "The selected remote worker policy cannot be read or parsed.",
            "worker_id": "—",
        }
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
        return {
            "configured": True,
            "enabled": False,
            "state": "unsafe permissions",
            "detail": "The remote worker policy must be an owner-controlled regular file.",
            "worker_id": "—",
        }
    enabled = payload.get("enabled") is True
    worker_id = str(payload.get("worker_id") or "—")[:128]
    return {
        "configured": True,
        "enabled": enabled,
        "state": "configured" if enabled else "gated",
        "detail": (
            "Restricted SSH transport is selected; use the readiness command to verify the host."
            if enabled
            else "The remote bridge policy exists but remains disabled in this runtime."
        ),
        "worker_id": worker_id,
    }
