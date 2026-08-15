from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from django.core.management import call_command
from governance_test_support import add_identity, make_governance_store, prepare_identities

from vulnhunter.source_hunt.controlled_corpus import ControlledCorpusDraft
from vulnhunter.source_hunt.controlled_fixture import (
    ControlledFixtureCompiler,
    ControlledFixtureDefinition,
)
from vulnhunter.source_hunt.service import SourceHuntPolicy

_AUTHOR_SECRET = "corpus-author-secret-123"


def _fixture_root() -> Path:
    return (
        Path(__file__).resolve().parents[2] / "benchmarks" / "source_hunt" / "controlled_python_v1"
    )


def _definition(root: Path | None = None) -> ControlledFixtureDefinition:
    base = root or _fixture_root()
    return ControlledFixtureDefinition.model_validate_json(
        (base / "definition.json").read_text(encoding="utf-8")
    )


def test_marker_defined_fixture_compiles_ten_balanced_exact_cases() -> None:
    root = _fixture_root()
    compiled = ControlledFixtureCompiler(
        policy=SourceHuntPolicy(
            approved_roots=(root.parent,),
            maximum_files=20,
            maximum_repository_bytes=1_000_000,
        )
    ).compile(root, definition=_definition())

    assert compiled.snapshot.revision == compiled.snapshot.snapshot_sha256
    assert len(compiled.corpus.cases) == 10
    assert sum(case.expected_vulnerable for case in compiled.corpus.cases) == 5
    assert sum(not case.expected_vulnerable for case in compiled.corpus.cases) == 5
    assert len({case.case_id for case in compiled.corpus.cases}) == 10
    assert len({line for _marker, line in compiled.marker_lines}) == 10
    assert compiled.production_accuracy_claim_permitted is False


def test_marker_drift_fails_closed(tmp_path) -> None:
    source = _fixture_root()
    copied = tmp_path / "fixture"
    shutil.copytree(source, copied)
    app = copied / "app.py"
    app.write_text(
        app.read_text(encoding="utf-8").replace("VH-GT:PT-VULN", "VH-GT:PT-MOVED"),
        encoding="utf-8",
    )
    compiler = ControlledFixtureCompiler(policy=SourceHuntPolicy(approved_roots=(tmp_path,)))

    with pytest.raises(ValueError, match="must occur exactly once"):
        compiler.compile(copied, definition=_definition(copied))


def test_definition_rejects_path_escape_and_missing_safe_control() -> None:
    payload = {
        "corpus_id": "bad-controlled-fixture",
        "cases": [
            {
                "case_id": "BAD-1",
                "vulnerability_class": "path_traversal",
                "path": "../outside.py",
                "marker": "VH-GT:BAD-1",
                "expected_vulnerable": True,
                "rationale": "This deliberately invalid case attempts a repository path escape.",
            },
            {
                "case_id": "BAD-2",
                "vulnerability_class": "path_traversal",
                "path": "app.py",
                "marker": "VH-GT:BAD-2",
                "expected_vulnerable": False,
                "rationale": "This safe control exists only so path validation is reached.",
            },
        ],
    }
    with pytest.raises(ValueError):
        ControlledFixtureDefinition.model_validate(payload)

    payload["cases"][0]["path"] = "app.py"
    payload["cases"][1]["expected_vulnerable"] = True
    with pytest.raises(ValueError, match="safe control"):
        ControlledFixtureDefinition.model_validate(payload)


def test_definition_file_command_gets_creator_only_from_authenticated_governance(
    tmp_path, monkeypatch
) -> None:
    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
    add_identity(governance, "corpus-author", _AUTHOR_SECRET, ("reviewer",))
    root = _fixture_root()
    output = tmp_path / "controlled-corpus-draft.json"
    monkeypatch.setenv("VULNHUNTER_SOURCE_HUNT_ROOTS", str(root.parent))
    monkeypatch.setattr(
        "vulnhunter.web.management.commands.vh_create_source_hunt_corpus_draft.getpass.getpass",
        lambda _prompt: _AUTHOR_SECRET,
    )

    call_command(
        "vh_create_source_hunt_corpus_draft",
        repo=str(root),
        definition_file=str(root / "definition.json"),
        creator_id="corpus-author",
        governance_db=str(governance.path),
        output=str(output),
    )

    draft = ControlledCorpusDraft.model_validate_json(output.read_text(encoding="utf-8"))
    assert draft.created_by == "corpus-author"
    assert draft.corpus.corpus_id == "source-hunt-controlled-python-v1"
    assert len(draft.corpus.cases) == 10
    assert draft.fixture.snapshot_sha256 == draft.fixture.revision
