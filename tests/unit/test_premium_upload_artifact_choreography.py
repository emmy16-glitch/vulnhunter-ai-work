from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "vulnhunter/web/static/web/conversation-thread-client.js"
COORDINATOR = ROOT / "vulnhunter/web/static/web/conversation-upload-coordinator.js"
CSS = ROOT / "vulnhunter/web/static/web/conversation-upload.css"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_workspace_upload_card_separates_upload_validation_and_ready_states() -> None:
    javascript = _text(CLIENT)

    assert 'if (state === "uploading")' in javascript
    assert 'if (state === "processing")' in javascript
    assert 'if (state === "completed")' in javascript
    assert 'title: `${name} uploaded`' in javascript
    assert '"Upload bytes complete · validating the artifact and binding the assessment."' in javascript
    assert 'title: `${name} ready`' in javascript
    assert (
        '"Artifact validated · the server confirmed the assessment result for this upload."'
        in javascript
    )
    processing = javascript.split('if (state === "processing")', maxsplit=1)[1].split(
        'if (state === "completed")', maxsplit=1
    )[0]
    assert "percent" not in processing


def test_byte_progress_is_exact_and_only_rendered_for_measurable_upload_states() -> None:
    javascript = _text(CLIENT)

    assert "const percent = Math.floor((offset / total) * 100)" in javascript
    assert 'detail: `${percent}% · ${bytes}`' in javascript
    assert "if (presentation.measurable)" in javascript
    assert "progress.max = total" in javascript
    assert "progress.value = offset" in javascript
    assert 'progress.setAttribute("aria-label", `Uploaded ${formatBytes(offset)} of ${formatBytes(total)}`)' in javascript
    assert 'measurable: false' in javascript


def test_interrupted_upload_preserves_bytes_and_exposes_bounded_recovery() -> None:
    javascript = _text(CLIENT)
    coordinator = _text(COORDINATOR)

    assert 'if (state === "retrying")' in javascript
    assert "preserved; retrying safely" in javascript
    assert 'action.textContent = needsFile ? "Choose file again" : "Retry upload"' in javascript
    assert 'cancel.textContent = "Cancel upload"' in javascript
    assert '["queued", "uploading", "retrying"].includes(record.state)' in javascript
    assert 'window.VulnHunterUploads = { enqueue, retry, cancel, list: listRecords, resume: schedule }' in coordinator
    assert 'document.addEventListener("vh:upload-cancelled"' in javascript
    assert "clearProgress()" in javascript


def test_task_meter_binds_only_to_persisted_stage_measurement() -> None:
    javascript = _text(CLIENT)
    css = _text(CSS)

    assert "persistedStageProgress" in javascript
    assert "persisted stages complete" in javascript
    assert 'meter.dataset.progressMeasurement = "stage"' in javascript
    assert 'meter.setAttribute("aria-valuenow", String(completed))' in javascript
    assert 'meter.setAttribute("aria-valuemax", String(total))' in javascript
    assert "fill.style.width = `${(completed / total) * 100}%`" in javascript
    assert "meter.hidden = true" in javascript
    assert 'delete meter.dataset.progressMeasurement' in javascript
    assert ".vh-run-progress-meter:not([data-progress-measurement])" in css


def test_task_progress_updates_in_place_without_creating_another_run_card() -> None:
    javascript = _text(CLIENT)

    assert "const taskProgressObserver = new MutationObserver" in javascript
    assert 'target?.closest?.("[data-run-stages]")' in javascript
    assert 'node.matches("[data-run-stages]")' in javascript
    assert "tracks.forEach(syncTaskStageProgress)" in javascript
    assert "createElement(\"article\")" not in javascript
    assert "data-run-card" not in javascript


def test_upload_interaction_targets_remain_accessible_and_reduced_motion_safe() -> None:
    css = _text(CSS)

    assert ".vh-upload-actions button" in css
    assert "min-width: 44px" in css
    assert "min-height: 44px" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    reduced = css.split("@media (prefers-reduced-motion: reduce)", maxsplit=1)[1]
    assert "animation: none" in reduced
    assert "transition: none" in reduced
