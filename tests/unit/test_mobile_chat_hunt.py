from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunter.hunt import (
    CandidateRecord,
    CandidateState,
    CoverageCell,
    CoverageStatus,
    HuntAltitude,
    raise_scrutiny,
    transition_candidate,
)
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.mobile_conversation import build_mobile_chat_plan

ROOT = Path(__file__).resolve().parents[2]


def _artifact(tmp_path: Path, *, native: bool) -> MobileArtifactRecord:
    apk = tmp_path / "original.apk"
    apk.write_bytes(b"test-apk")
    return MobileArtifactRecord(
        artifact_id="apk-0123456789abcdef01234567",
        original_filename="banking-app.apk",
        stored_path=apk,
        sha256="a" * 64,
        size_bytes=8,
        archive_entry_count=4,
        total_uncompressed_bytes=8,
        manifest_entry="AndroidManifest.xml",
        dex_entries=("classes.dex",),
        native_libraries=("lib/arm64-v8a/libsecure.so",) if native else (),
        native_abis=("arm64-v8a",) if native else (),
    )


def _attachment(*, native: bool) -> ConversationAttachment:
    return ConversationAttachment(
        attachment_id="attachment-0123456789abcdef0123",
        kind="android_apk",
        artifact_id="apk-0123456789abcdef01234567",
        artifact_sha256="a" * 64,
        original_filename="banking-app.apk",
        size_bytes=8,
        archive_entry_count=4,
        dex_count=1,
        native_library_count=1 if native else 0,
        native_abis=("arm64-v8a",) if native else (),
        created_at="2026-07-25T12:00:00+00:00",
    )


def test_full_mobile_chat_request_prepares_static_native_hunt_and_defers_runtime(tmp_path):
    plan = build_mobile_chat_plan(
        text="Do a full deep test of this APK",
        requested_by="VulnHunter User",
        attachment=_attachment(native=True),
        artifact=_artifact(tmp_path, native=True),
    )

    tool_ids = {item["tool_id"] for item in plan["tools"]}
    altitudes = [item["altitude"] for item in plan["rounds"]]

    assert plan["requested_profile"] == "full"
    assert plan["profile"] == "static_and_native"
    assert plan["dynamic_deferred"] is True
    assert {"apktool", "jadx", "radare2", "ghidra"} <= tool_ids
    assert "nmap" not in tool_ids
    assert "nuclei" not in tool_ids
    assert "native" in altitudes
    assert "runtime" in altitudes
    assert altitudes[-1] == "variant_sweep"
    assert len(plan["plan_digest"]) == 64


def test_default_apk_request_uses_static_profile_when_no_native_libraries(tmp_path):
    plan = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="analyst",
        attachment=_attachment(native=False),
        artifact=_artifact(tmp_path, native=False),
    )

    tool_ids = {item["tool_id"] for item in plan["tools"]}
    assert plan["requested_profile"] == "static"
    assert plan["profile"] == "static"
    assert plan["dynamic_deferred"] is False
    assert "jadx" in tool_ids
    assert "radare2" not in tool_ids
    assert all(item["altitude"] != "runtime" for item in plan["rounds"])


def test_hunt_scrutiny_is_monotonic_and_receipt_bound():
    cell = CoverageCell(
        cell_id="cell-01",
        altitude=HuntAltitude.CODE,
        object_reference="class-a",
        weakness_class="unsafe-webview",
    )
    raised = raise_scrutiny(
        cell,
        new_level=2,
        evidence_receipt="evidence-sha256",
        status=CoverageStatus.COVERED,
    )

    assert raised.scrutiny_level == 2
    assert raised.attempts == 1
    assert raised.evidence_receipts == ("evidence-sha256",)
    with pytest.raises(ValueError, match="cannot be lowered"):
        raise_scrutiny(raised, new_level=1, evidence_receipt="other-receipt")


def test_candidate_cannot_jump_to_confirmed_or_be_rejected_without_receipt():
    candidate = CandidateRecord(
        candidate_id="candidate-01",
        weakness_id="cwe-926",
        title="Exported component may lack permission protection",
    )

    with pytest.raises(ValueError, match="not allowed"):
        transition_candidate(
            candidate,
            new_state=CandidateState.CONFIRMED,
            disposition_reason="Skipped verification",
            evidence_receipt="receipt",
        )
    with pytest.raises(ValueError, match="requires an evidence or judge receipt"):
        transition_candidate(
            candidate,
            new_state=CandidateState.REJECTED,
            disposition_reason="No longer believed",
        )


def test_conversation_ui_exposes_plus_button_and_progressive_mobile_assets():
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(encoding="utf-8")
    script = (ROOT / "vulnhunter/web/static/web/conversation-mobile.js").read_text(encoding="utf-8")

    assert "data-conversation-attach" in template
    assert "data-conversation-file" in template
    assert "web-conversation-attachment" in template
    assert "web-conversation-mobile-message" in template
    assert 'setTimeout(() => item.classList.add("is-visible")' in script
    assert "stopImmediatePropagation" in script
