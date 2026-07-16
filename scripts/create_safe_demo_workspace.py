#!/usr/bin/env python3
"""Create clearly-labelled local demo data without scans or external calls."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path


def main() -> int:
    created_at = datetime.now(UTC).isoformat()
    payload = {
        "schema_version": "1.0",
        "demo": True,
        "simulation_only": True,
        "created_at": created_at,
        "target": "demo.internal.invalid",
        "authorization": "simulated-local-only",
        "assessment": {
            "run_id": "demo-assessment-001",
            "state": "waiting_for_human_approval",
            "progress_percent": 42,
            "active_stage": "bounded-active-validation-request",
        },
        "finding": {
            "title": "Demonstration finding — not observed on a real target",
            "severity": "high",
            "verification": "simulated",
            "evidence": [],
        },
        "oracle": {"state": "simulated-degraded", "live_connector": False},
        "external_actions_performed": False,
    }
    canonical = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    destination = Path("var/demo/vulnhunter-safe-demo.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(canonical, encoding="utf-8")
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    manifest = {
        "artifact": destination.as_posix(),
        "sha256": digest,
        "simulation_only": True,
        "external_actions_performed": False,
    }
    Path("var/demo/manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Created safe simulated demo: {destination}")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
