from __future__ import annotations

import pytest

from vulnhunter.realtime.consumers import AssessmentEventsConsumer


@pytest.mark.asyncio
async def test_snapshot_includes_activity_tree_and_cursor() -> None:
    consumer = object.__new__(AssessmentEventsConsumer)
    consumer.assessment_id = "assessment-realtime"

    async def payload(after_sequence: int):
        return {
            "events": [{"sequence": after_sequence + 1, "event_type": "tool_progress"}],
            "last_sequence": after_sequence + 1,
            "run_state": "executing",
            "terminal": False,
            "activity_tree": {
                "schema_version": "1.0",
                "task_id": "assessment-realtime",
                "status": "running",
                "last_sequence": after_sequence + 1,
                "nodes": [
                    {
                        "activity_id": "assessment-realtime:stage:tools",
                        "status": "running",
                        "label": "Tool execution",
                        "children": [],
                    }
                ],
            },
        }

    consumer._payload = payload
    snapshot = await consumer._snapshot(7)

    assert snapshot["type"] == "assessment.snapshot"
    assert snapshot["assessment_id"] == "assessment-realtime"
    assert snapshot["last_sequence"] == 8
    assert snapshot["activity_tree"]["task_id"] == "assessment-realtime"
    assert snapshot["activity_tree"]["status"] == "running"
