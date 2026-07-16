import pytest

from vulnhunter.evidence import EvidenceStore, FindingStatus
from vulnhunter.evidence.store import EvidenceStoreError


def test_evidence_store_hashes_artifacts_and_detects_tampering(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    artifact = root / "result.json"
    artifact.write_text('{"ok": true}\n', encoding="utf-8")

    store = EvidenceStore(root)
    record = store.append(
        evidence_id="evidence-01",
        campaign_id="campaign-01",
        run_id="run-01",
        action_manifest_sha256="a" * 64,
        tool_id="nuclei",
        target_reference="target-01",
        finding_status=FindingStatus.CANDIDATE,
        title="Candidate web security finding",
        severity="medium",
        confidence="candidate",
        recorded_by="scanner-01",
        artifact_path=artifact,
    )
    assert record.artifact_sha256
    assert len(store.list()) == 1

    artifact.write_text('{"ok": false}\n', encoding="utf-8")
    with pytest.raises(EvidenceStoreError, match="artifact digest"):
        store.list()
