"""Contract tests for bounded orchestration specifications."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnhunter.orchestration.models import LoopSpec, VerifierKind, normalize_actor_id


def valid_spec_data() -> dict[str, object]:
    return {
        "title": "Bounded example change",
        "objective": ("Implement one bounded example change with deterministic proof and review."),
        "required_context": ("AGENTS.md",),
        "allowed_actions": (
            "edit_allowed_files",
            "run_deterministic_verifiers",
            "record_redacted_evidence",
            "update_documentation",
        ),
        "allowed_paths": ("src/**", "docs/change.md"),
        "verifiers": (VerifierKind.GIT_DIFF_CHECK,),
        "required_evidence": ("Diff check",),
        "recovery_instructions": ("Stop and inspect evidence.",),
        "documentation_paths": ("docs/**",),
    }


def test_loop_spec_requires_all_bounded_actions() -> None:
    data = valid_spec_data()
    data["allowed_actions"] = ("edit_allowed_files",)

    with pytest.raises(ValidationError, match="all four bounded loop actions"):
        LoopSpec(**data)


def test_loop_spec_rejects_path_traversal() -> None:
    data = valid_spec_data()
    data["allowed_paths"] = ("../outside.py",)

    with pytest.raises(ValidationError, match="traversal-free"):
        LoopSpec(**data)


def test_loop_spec_rejects_duplicate_verifiers() -> None:
    data = valid_spec_data()
    data["verifiers"] = (
        VerifierKind.GIT_DIFF_CHECK,
        VerifierKind.GIT_DIFF_CHECK,
    )

    with pytest.raises(ValidationError, match="unique"):
        LoopSpec(**data)


def test_actor_ids_are_stable_pseudonyms() -> None:
    assert normalize_actor_id(" Reviewer.One ") == "reviewer.one"

    with pytest.raises(ValueError, match="Actor IDs"):
        normalize_actor_id("A")
