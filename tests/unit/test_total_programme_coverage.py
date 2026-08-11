from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "generate_total_programme_coverage.py"


def _load_audit_module():
    spec = importlib.util.spec_from_file_location("programme_authority_audit", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_current_document_authority_chain_is_reconciled() -> None:
    audit_module = _load_audit_module()

    results = audit_module.audit(ROOT)
    assert results
    assert all(result.ok for result in results), [
        (result.path, result.detail) for result in results if not result.ok
    ]

    rendered = audit_module.render(results)
    assert "Transition gate: `PASS`" in rendered
    assert "Failed checks: `0`" in rendered
    assert "PUBLIC_TARGET_ASSESSMENT.md" in rendered
    assert "LIVE_EXECUTION_ACTIVITY.md" in rendered


def test_retired_future_plan_is_not_current_roadmap() -> None:
    future = (ROOT / "docs/intelligence/VULNHUNTER_FUTURE_MASTER_PLAN.md").read_text(
        encoding="utf-8"
    )
    roadmap = (ROOT / "docs/intelligence/ROADMAP.md").read_text(encoding="utf-8")
    current = (ROOT / "docs/intelligence/CURRENT_STATE.md").read_text(encoding="utf-8")

    assert "RETIRED AS AN AUTHORITY SOURCE" in future
    assert "Authorised public-target passive execution" in roadmap
    assert "Persisted live execution activity" in roadmap
    assert "PUBLIC-TARGET WORKER EXECUTION" in current
    assert "NOT COMPLETE" in current


def test_public_target_programme_preserves_authorization_and_transport_boundaries() -> None:
    public_contract = (ROOT / "docs/product/PUBLIC_TARGET_ASSESSMENT.md").read_text(
        encoding="utf-8"
    )
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "A public address is not permission" in public_contract
    assert "Connection-time revalidation" in public_contract
    assert "Host and TLS identity preservation" in public_contract
    assert "Do not implement public support by globally setting `allow_public=True`" in agents
    assert "private-only worker continues to reject public jobs" in agents


def test_live_execution_contract_requires_persisted_operational_activity() -> None:
    live = (ROOT / "docs/product/LIVE_EXECUTION_ACTIVITY.md").read_text(encoding="utf-8")

    assert "operational telemetry" in live
    assert "One persisted activity stream" in live
    assert "hidden chain-of-thought" in live
    assert "reconnect" in live.casefold()
    assert "deduplicate" in live.casefold()
