#!/usr/bin/env python3
"""Apply the stale completed-run conversation hotfix exactly once."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"Expected patch context was not found in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    views = ROOT / "vulnhunter/web/conversational_views.py"
    state = ROOT / "vulnhunter/web/conversation_state.py"

    replace_once(
        views,
        "    return _latest_visible_run(actor, target=target)\n",
        "    if target:\n"
        "        return _latest_visible_run(actor, target=target)\n"
        "    return None\n",
    )

    replace_once(
        state,
        '''    if payload:\n        if re.search(r"\\b(link|url|address|target)\\b", lowered):\n            target = _text(payload.get("target"))\n            if target:\n                return f"The authoritative target for the current assessment is {target}."\n        if "approval" in lowered:\n            if payload.get("approval"):\n                return "The exact passive plan is waiting for your confirmation below."\n            approval_state = _text(payload.get("approval_state")) or "not required"\n            return f"The current approval state is {approval_state}."\n        return (\n            f"I am tracking the current assessment for {_text(payload.get('target'))}. "\n            f"{_text(payload.get('current_step'))} You can ask for status, results, "\n            "evidence or the next step."\n        )\n    return fallback or (\n        "Paste an authorised http or https target. I will check scope, prepare the passive plan, "\n        "pause for confirmation and report progress in this conversation."\n    )\n''',
        '''    if payload:\n        if re.search(r"\\b(link|url|address|target)\\b", lowered):\n            target = _text(payload.get("target"))\n            if target:\n                return f"The authoritative target for the current assessment is {target}."\n        if "approval" in lowered:\n            if payload.get("approval"):\n                return "The exact passive plan is waiting for your confirmation below."\n            approval_state = _text(payload.get("approval_state")) or "not required"\n            return f"The current approval state is {approval_state}."\n    if fallback:\n        return fallback\n    if payload:\n        return (\n            f"I am tracking the selected assessment for {_text(payload.get('target'))}. "\n            "Ask for its status, results, evidence or next step, or paste another authorised "\n            "website to prepare a new assessment."\n        )\n    return (\n        "Paste an authorised http or https target. I will check scope, prepare the passive plan, "\n        "pause for confirmation and report progress in this conversation."\n    )\n''',
    )

    test_path = ROOT / "tests/unit/test_stale_conversation_state.py"
    if not test_path.exists():
        test_path.write_text(
            '''from __future__ import annotations\n\nfrom types import SimpleNamespace\n\nfrom vulnhunter.web import conversational_views\nfrom vulnhunter.web.conversation_state import contextual_chat_reply\n\n\ndef test_ordinary_chat_is_not_replaced_by_completed_run_status() -> None:\n    payload = {\n        "target": "http://10.0.11.34:8010/",\n        "current_step": "Analysis complete.",\n        "approval": None,\n    }\n\n    reply = contextual_chat_reply(\n        "What can you do?",\n        payload,\n        "I can prepare and explain a new authorised assessment.",\n    )\n\n    assert reply == "I can prepare and explain a new authorised assessment."\n    assert "tracking the current assessment" not in reply.casefold()\n\n\ndef test_new_conversation_does_not_attach_latest_completed_run(monkeypatch) -> None:\n    latest = SimpleNamespace(run_id="old-completed-run")\n    monkeypatch.setattr(\n        conversational_views,\n        "_latest_visible_run",\n        lambda actor, target=None: latest,\n    )\n\n    assert conversational_views._authoritative_run({}, object()) is None\n    assert (\n        conversational_views._authoritative_run(\n            {},\n            object(),\n            target="http://10.0.1.51:8010/",\n        )\n        is latest\n    )\n\n\ndef test_explicit_session_run_remains_authoritative(monkeypatch) -> None:\n    selected = SimpleNamespace(\n        run_id="selected-run",\n        scope_summary="http://10.0.1.51:8010/",\n        objective="",\n    )\n    monkeypatch.setattr(conversational_views, "_visible_run", lambda run_id, actor: selected)\n\n    resolved = conversational_views._authoritative_run(\n        {"run_id": "selected-run"},\n        object(),\n    )\n\n    assert resolved is selected\n''',
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
