from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "opensandbox-worker-release.yml"
_ACTION_REF = re.compile(r"^uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
_EXPECTED_ACTIONS = {
    "uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f",
    "uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
    "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
    "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
}


def test_production_worker_release_workflow_keeps_authority_separation() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    trigger_block = text.split("permissions:", 1)[0]

    assert "workflow_dispatch:" in trigger_block
    assert "pull_request:" not in trigger_block
    assert "\n  push:" not in trigger_block
    assert "permissions: {}" in text
    assert 'GITHUB_REF" != "refs/heads/main"' in text
    assert "PUBLISH_OPEN_SANDBOX_WORKER" in text
    assert "inputs.source_commit" not in text
    assert "--status candidate" in text
    assert "--status approved" not in text
    assert "--status revoked" not in text
    assert "--private-key" not in text
    assert "persist-credentials: false" in text
    assert '--source-digest "$GITHUB_SHA"' in text
    assert "--deny-self-hosted-runners" in text
    assert "create-storage-record: false" in text
    assert "secrets.GITHUB_TOKEN" in text
    assert "OPEN_SANDBOX_API_KEY" not in text

    uses = {line.strip() for line in text.splitlines() if line.strip().startswith("uses: ")}
    assert _EXPECTED_ACTIONS <= uses
    assert all(_ACTION_REF.fullmatch(line) for line in uses)
