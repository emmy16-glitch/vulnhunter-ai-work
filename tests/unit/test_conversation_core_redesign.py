from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.web.conversation_service import deterministic_intent
from vulnhunter.web.conversation_state import enrich_run_payload, reply_for_intent
from vulnhunter.web.conversational_views import _normalize_message_copy


def base_payload(**updates):
    now = datetime.now(UTC)
    payload = {
        "run_id": "assessment-test",
        "state": "running",
        "target": "http://10.0.11.34:8010/",
        "profile": "passive",
        "created_at": (now - timedelta(seconds=12)).isoformat(),
        "updated_at": now.isoformat(),
        "terminal": False,
        "approval": None,
        "approval_state": "approved",
        "blocking_reason": None,
        "findings": [],
        "artifacts": [],
    }
    payload.update(updates)
    return payload


def test_deterministic_commands_are_distinct():
    assert deterministic_intent("Confirm") == "approve"
    assert deterministic_intent("Show me the results") == "results"
    assert deterministic_intent("Next step") == "next_step"
    assert deterministic_intent("What is happening?") == "status"
    assert deterministic_intent("Cancel it") == "cancel"


def test_status_results_and_next_step_do_not_share_canned_copy():
    payload = enrich_run_payload(
        base_payload(),
        raw_events=[
            {
                "event_type": "scanner_started",
                "summary": "Running passive checks…",
                "sequence": 1,
            }
        ],
        template_count=7,
    )
    status = reply_for_intent("status", payload)
    results = reply_for_intent("results", payload)
    next_step = reply_for_intent("next_step", payload)
    assert len({status, results, next_step}) == 3
    assert "Running 7 reviewed passive checks" in status
    assert "not finished" in results
    assert "No action is required" in next_step


def test_completed_projection_filters_provider_failures_and_returns_evidence_summary():
    payload = enrich_run_payload(
        base_payload(
            state="completed",
            terminal=True,
            findings=[
                {
                    "title": "Missing X-Content-Type-Options header",
                    "severity": "info",
                }
            ],
            artifacts=[{"filename": "headers.json"}],
        ),
        raw_events=[
            {
                "event_type": "provider_notice",
                "summary": "Advisory reasoning abstained: provider stage unavailable",
                "sequence": 1,
            },
            {
                "event_type": "run_completed",
                "summary": "Analysis complete.",
                "sequence": 2,
            },
        ],
        template_count=7,
    )
    assert len(payload["events"]) == 1
    assert "provider stage unavailable" not in payload["final_message"].lower()
    assert "Missing X-Content-Type-Options" in payload["final_message"]
    assert "deterministic verification" in payload["analysis_note"]


def test_message_copy_preserves_progressive_lines():
    copy = _normalize_message_copy(
        "Target:\nhttp://10.0.11.34:8010/\n\nChecking authorisation… completed"
    )
    assert copy == ("Target:\nhttp://10.0.11.34:8010/\nChecking authorisation… completed")
