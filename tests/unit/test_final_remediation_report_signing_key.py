from __future__ import annotations

import pytest

from vulnhunter.reports import FinalRemediationReportError
from vulnhunter.web.final_report_service import final_report_signing_key


def test_final_report_signing_key_accepts_owner_private_file(
    tmp_path,
    settings,
    monkeypatch,
):
    path = tmp_path / "final-report-signing-key"
    path.write_bytes(b"r" * 32)
    path.chmod(0o600)
    settings.VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE = str(path)
    monkeypatch.delenv("VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE", raising=False)

    assert final_report_signing_key() == b"r" * 32


def test_final_report_signing_key_rejects_group_or_world_access(
    tmp_path,
    settings,
    monkeypatch,
):
    path = tmp_path / "final-report-signing-key"
    path.write_bytes(b"r" * 32)
    path.chmod(0o644)
    settings.VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE = str(path)
    monkeypatch.delenv("VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE", raising=False)

    with pytest.raises(FinalRemediationReportError, match="owner-private"):
        final_report_signing_key()


def test_final_report_signing_key_rejects_short_material(
    tmp_path,
    settings,
    monkeypatch,
):
    path = tmp_path / "final-report-signing-key"
    path.write_bytes(b"short")
    path.chmod(0o600)
    settings.VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE = str(path)
    monkeypatch.delenv("VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE", raising=False)

    with pytest.raises(FinalRemediationReportError, match="at least 32 bytes"):
        final_report_signing_key()
