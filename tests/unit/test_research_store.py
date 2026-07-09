"""Tests for experiment evidence and hash-chain persistence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.unit.test_research_models import valid_spec
from vulnhunter.exceptions import ResearchIntegrityError
from vulnhunter.research.boundaries import (
    default_evaluator_policy,
    policy_sha256,
    protected_snapshot_sha256,
)
from vulnhunter.research.meta import default_search_policy
from vulnhunter.research.models import ExperimentManifest, ProtectedSnapshot
from vulnhunter.research.store import ResearchStore


def _records(store: Path) -> tuple[ExperimentManifest, ProtectedSnapshot]:
    now = datetime.now(UTC)
    policy_hash = policy_sha256(default_evaluator_policy())
    provisional = ProtectedSnapshot(
        created_at=now,
        repository_commit="a" * 40,
        policy_sha256=policy_hash,
        files=(),
        snapshot_sha256="0" * 64,
    )
    snapshot = provisional.model_copy(
        update={"snapshot_sha256": protected_snapshot_sha256(provisional)}
    )
    manifest = ExperimentManifest(
        experiment_id="exp-20260709-test1234",
        spec=valid_spec(),
        creator_id="creator.one",
        builder_id="builder.one",
        repository_root="/tmp/repo",
        store_root=str(store),
        baseline_commit="a" * 40,
        baseline_tree="b" * 40,
        policy_sha256=policy_hash,
        protected_snapshot_sha256=snapshot.snapshot_sha256,
        created_at=now,
        updated_at=now,
    )
    return manifest, snapshot


def test_store_verifies_manifest_and_event_chain(tmp_path: Path) -> None:
    store = ResearchStore(tmp_path / "research")
    manifest, snapshot = _records(store.root)
    store.create(manifest, policy=default_evaluator_policy(), snapshot=snapshot)
    store.append_event(
        manifest.experiment_id,
        "experiment_created",
        "creator.one",
        {"baseline": manifest.baseline_commit},
    )

    loaded, events = store.verify_integrity(manifest.experiment_id)

    assert loaded.experiment_id == manifest.experiment_id
    assert len(events) == 1


def test_store_detects_manifest_tampering(tmp_path: Path) -> None:
    store = ResearchStore(tmp_path / "research")
    manifest, snapshot = _records(store.root)
    store.create(manifest, policy=default_evaluator_policy(), snapshot=snapshot)
    path = store.experiment_directory(manifest.experiment_id) / "manifest.json"
    path.write_text(path.read_text().replace("draft", "accepted"))

    with pytest.raises(ResearchIntegrityError, match="integrity"):
        store.load(manifest.experiment_id)


def test_store_detects_event_tampering(tmp_path: Path) -> None:
    store = ResearchStore(tmp_path / "research")
    manifest, snapshot = _records(store.root)
    store.create(manifest, policy=default_evaluator_policy(), snapshot=snapshot)
    store.append_event(manifest.experiment_id, "created", "creator.one", {"x": 1})

    path = store.experiment_directory(manifest.experiment_id) / "events.jsonl"
    records = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]

    assert records[0]["payload"]["x"] in {"1", 1}

    records[0]["payload"]["x"] = "2"
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records)
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ResearchIntegrityError, match="invalid|integrity"):
        store.verify_integrity(manifest.experiment_id)


def test_search_policy_digest_detects_tampering(tmp_path: Path) -> None:
    store = ResearchStore(tmp_path / "research")
    store.save_search_policy(default_search_policy())
    path = store.root / "search-policy.json"
    path.write_text(
        path.read_text(encoding="utf-8").replace('"generation": 0', '"generation": 9'),
        encoding="utf-8",
    )

    with pytest.raises(ResearchIntegrityError, match="integrity"):
        store.load_search_policy()
