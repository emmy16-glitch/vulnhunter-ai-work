from pathlib import Path

BRIDGE = Path("vulnhunter/web/static/web/conversation-mobile-bridge.js")
STORE = Path("vulnhunter/web/static/web/workspace-state.js")


def _source() -> str:
    return BRIDGE.read_text(encoding="utf-8")


def test_mobile_retry_control_uses_authoritative_projection_contract() -> None:
    source = _source()

    assert "retry?.available !== true" in source
    assert 'actions.includes("request_retry")' in source
    assert 'const scope = String(retry.scope || "")' in source
    assert 'body.append("retry_scope", scope)' in source
    assert 'body.append("idempotency_key", idempotencyKey)' in source


def test_mobile_retry_control_preserves_idempotency_key_after_unknown_failure() -> None:
    source = _source()

    clear_call = "clearRetryIdempotencyKey(assessmentId, scope);"
    success_check = "if (!response.ok) throw new Error"
    error_handler = "} catch (error) {"

    assert source.index(success_check) < source.index(clear_call)
    assert source.index(clear_call) < source.index(error_handler)
    assert "button.disabled = false;" in source[source.index(error_handler) :]


def test_mobile_retry_control_restores_server_owned_state_after_reconnect() -> None:
    source = _source()

    assert 'method: "GET"' in source
    assert 'cache: "no-store"' in source
    assert "window.setTimeout(refreshSelectedAssessment, 0)" in source
    assert "replaceSelectedAssessment(payload);" in source
    assert "if (!retryCard())" in source


def test_mobile_refresh_cannot_overwrite_newer_authoritative_state() -> None:
    source = _source()

    assert "let refreshGeneration = 0;" in source
    assert "const invalidatePendingRefresh = () =>" in source
    assert "const generation = ++refreshGeneration;" in source
    assert source.count("if (generation !== refreshGeneration) return;") == 2
    assert source.index("invalidatePendingRefresh();") < source.index(
        "withAssessmentStore((store) => store.replace(payload || {}));"
    )
    assert source.index("invalidatePendingRefresh();", source.index("const clearSelectedAssessment")) < source.index(
        "withAssessmentStore((store) => store.clear());"
    )


def test_mobile_retry_control_keeps_csrf_and_session_boundaries() -> None:
    source = _source()

    assert 'credentials: "same-origin"' in source
    assert '"X-CSRFToken": csrfToken()' in source
    assert 'retryUrl = "/workspace/mobile-retry/"' in source


def test_mobile_task_activity_uses_selected_assessment_store_only() -> None:
    source = _source()
    store = STORE.read_text(encoding="utf-8")

    assert "window.vhSelectedAssessmentStore" in source
    assert '"vh:selected-assessment-store-ready"' in source
    assert "store.replace(payload || {})" in source
    assert "store.clear()" in source
    assert "store.subscribe(renderSelectedAssessment)" in source
    assert '"vh:mobile-projection"' not in source
    assert '"vh:mobile-reset"' not in source
    assert '"vh:mobile-projection"' not in store
    assert '"vh:mobile-reset"' not in store


def test_mobile_task_activity_uses_authoritative_task_card_only() -> None:
    source = _source()

    assert "const taskCard = snapshot?.task_card" in source
    assert "taskCard.assessment_id !== projection?.assessment_id" in source
    assert 'panel.dataset.mobileTaskProjection = ""' in source
    assert 'panel.setAttribute("aria-label", "Assessment activity")' in source


def test_mobile_task_activity_uses_measured_progress_without_percentages() -> None:
    source = _source()

    assert "taskCard.stage_progress?.completed" in source
    assert "taskCard.stage_progress?.total" in source
    assert "taskCard.byte_progress" in source
    assert "received <= expected" in source
    assert "recorded stages complete" in source
    assert "progress_percent" not in source


def test_mobile_task_activity_renders_persisted_counts_and_latest_event() -> None:
    source = _source()

    assert "activity.event_count" in source
    assert "activity.receipt_count" in source
    assert "activity.candidate_count" in source
    assert "activity.latest_event" in source
    assert "evidence receipts" in source


def test_mobile_task_activity_renders_authoritative_stage_timeline() -> None:
    source = _source()

    assert "Array.isArray(projection?.stages)" in source
    assert 'details.dataset.mobileActivityTimeline = ""' in source
    assert 'list.setAttribute("aria-label", "Persisted assessment stages")' in source
    assert "row.dataset.stageStatus = status" in source
    assert 'summary.textContent = "Recorded stage timeline"' in source
    assert "renderStageTimeline(projection)" in source


def test_mobile_task_activity_ignores_incomplete_timeline_rows() -> None:
    source = _source()

    assert 'const stage = String(item?.stage || "").trim();' in source
    assert 'const status = String(item?.status || "").trim();' in source
    assert "if (!stage || !status) return;" in source
    assert "if (!list.children.length) return null;" in source


def test_mobile_task_activity_is_removed_when_authoritative_selection_clears() -> None:
    source = _source()

    assert "if (!snapshot)" in source
    assert "removeMobileProjectionControls();" in source
    assert "[data-mobile-task-projection], [data-mobile-retry-control]" in source
    assert "clearSelectedAssessment" in source
