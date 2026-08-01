from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunter.governance.release_package import (
    CampaignReleasePackageError,
    CampaignReleasePackageStore,
)


def test_release_package_store_rejects_path_like_campaign_and_release_ids(
    tmp_path: Path,
) -> None:
    store = CampaignReleasePackageStore(tmp_path / "packages")

    with pytest.raises(CampaignReleasePackageError, match="campaign ID"):
        store.load("../outside", "release-safe")
    with pytest.raises(CampaignReleasePackageError, match="release ID"):
        store.load("campaign-safe", "../outside")

    assert not (tmp_path / "outside").exists()
