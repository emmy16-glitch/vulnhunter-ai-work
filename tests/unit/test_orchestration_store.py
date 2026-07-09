"""Persistence and audit-integrity tests for orchestration loops."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from vulnhunter.exceptions import LoopIntegrityError
from vulnhunter.orchestration.models import LoopManifest, LoopSpec, VerifierKind
from vulnhunter.orchestration.store import LoopStore


def make_manifest() -> LoopManifest:
    now = datetime.now(UTC)
    spec = LoopSpec(
        title="Store integrity test",
        objective="Verify atomic manifests and hash-chained append-only event integrity.",
        required_context=("AGENTS.md",),
        allowed_actions=(
            "edit_allowed_files",
            "run_deterministic_verifiers",
            "record_redacted_evidence",
            "update_documentation",
        ),
        allowed_paths=("src/**", "docs/**"),
        verifiers=(VerifierKind.GIT_DIFF_CHECK,),
        required_evidence=("Git diff evidence",),
        recovery_instructions=("Stop and inspect the event chain.",),
        documentation_paths=("docs/**",),
    )
    return LoopManifest(
        loop_id="loop-20260709-test0001",
        spec=spec,
        creator_id="human.owner",
        builder_id="builder.agent",
        repository_root="/tmp/repository",
        baseline_commit="a" * 40,
        baseline_tree="b" * 40,
        created_at=now,
        updated_at=now,
    )


def test_event_chain_round_trip(tmp_path) -> None:
    store = LoopStore.from_path(tmp_path / "loops")
    manifest = make_manifest()
    store.create(manifest)
    first = store.append_event(
        manifest.loop_id,
        "loop_created",
        "human.owner",
        {"token": "secret-value", "status": "created"},
    )
    second = store.append_event(
        manifest.loop_id,
        "verification_completed",
        "test.runner",
        {"passed": True},
    )

    events = store.verify_event_chain(manifest.loop_id)

    assert len(events) == 2
    assert second.previous_hash == first.event_hash
    assert events[0].payload["token"] == "[REDACTED]"


def test_event_chain_detects_tampering(tmp_path) -> None:
    store = LoopStore.from_path(tmp_path / "loops")
    manifest = make_manifest()
    store.create(manifest)
    store.append_event(
        manifest.loop_id,
        "loop_created",
        "human.owner",
        {"status": "created"},
    )

    event_path = store.loop_directory(manifest.loop_id) / "events.jsonl"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    event["payload"]["status"] = "tampered"
    event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(LoopIntegrityError, match="failed integrity"):
        store.verify_event_chain(manifest.loop_id)


def test_store_refuses_duplicate_loop_creation(tmp_path) -> None:
    store = LoopStore.from_path(tmp_path / "loops")
    manifest = make_manifest()
    store.create(manifest)

    with pytest.raises(LoopIntegrityError, match="already exists"):
        store.create(manifest)


def test_manifest_digest_detects_tampering(tmp_path) -> None:
    store = LoopStore.from_path(tmp_path / "loops")
    manifest = make_manifest()
    store.create(manifest)

    path = store.loop_directory(manifest.loop_id) / "manifest.json"
    path.write_text(
        path.read_text(encoding="utf-8").replace("active", "completed"),
        encoding="utf-8",
    )

    with pytest.raises(LoopIntegrityError, match="manifest failed integrity"):
        store.load(manifest.loop_id)
