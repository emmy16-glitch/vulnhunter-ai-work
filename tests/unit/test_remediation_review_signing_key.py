from __future__ import annotations

import pytest

from vulnhunter.findings import RemediationReviewError
from vulnhunter.web.remediation_review_service import remediation_review_signing_key


def test_remediation_review_signing_key_accepts_owner_private_file(
    tmp_path,
    settings,
    monkeypatch,
):
    path = tmp_path / "review-signing-key"
    path.write_bytes(b"r" * 32)
    path.chmod(0o600)
    settings.VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE = str(path)
    monkeypatch.delenv("VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE", raising=False)

    assert remediation_review_signing_key() == b"r" * 32


def test_remediation_review_signing_key_rejects_group_or_world_access(
    tmp_path,
    settings,
    monkeypatch,
):
    path = tmp_path / "review-signing-key"
    path.write_bytes(b"r" * 32)
    path.chmod(0o644)
    settings.VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE = str(path)
    monkeypatch.delenv("VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE", raising=False)

    with pytest.raises(RemediationReviewError, match="owner-private"):
        remediation_review_signing_key()


def test_remediation_review_signing_key_rejects_short_material(
    tmp_path,
    settings,
    monkeypatch,
):
    path = tmp_path / "review-signing-key"
    path.write_bytes(b"short")
    path.chmod(0o600)
    settings.VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE = str(path)
    monkeypatch.delenv("VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE", raising=False)

    with pytest.raises(RemediationReviewError, match="at least 32 bytes"):
        remediation_review_signing_key()
