"""Batch 3 assessment-workspace contract checks."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "vulnhunter" / "web"


def test_assessment_workspace_uses_persisted_projection_timeline() -> None:
    script = (WEB / "static" / "web" / "assessment-workspace.js").read_text(encoding="utf-8")
    template = (WEB / "templates" / "web" / "conversation.html").read_text(encoding="utf-8")

    assert "assessment_projection" in script
    assert "projection?.stages" in script
    assert "completed" in script
    assert "running" in script
    assert "pending" in script
    assert "blocked" in script
    assert "recovering" in script
    assert "failed" in script
    assert "cancelled" in script
    assert 'active: "running"' in script
    assert 'waiting: "pending"' in script
    assert 'data-run-stages aria-label="Persisted assessment timeline"' in template


def test_assessment_workspace_only_exposes_cancel_when_projection_allows_it() -> None:
    script = (WEB / "static" / "web" / "conversation.js").read_text(encoding="utf-8")
    template = (WEB / "templates" / "web" / "conversation.html").read_text(encoding="utf-8")

    assert 'allowed.includes("request_cancel")' in script
    assert "data-run-cancel hidden" in template
    assert ">Pause<" not in template


def test_assessment_workspace_does_not_run_a_browser_owned_elapsed_clock() -> None:
    script = (WEB / "static" / "web" / "conversation.js").read_text(encoding="utf-8")

    assert "data-run-stage-elapsed" not in script
    assert "window.setInterval(() => {\n    if (!runCard || !activeRun)" not in script
