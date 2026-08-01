from pathlib import Path


def replace_once(path: Path, old: str, new: str, *, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    Path("vulnhunter/web/remediation_views.py"),
    "    RemediationFixVerificationError,\n    RemediationState,\n",
    "    RemediationFixVerificationError,\n    RemediationReviewError,\n    RemediationState,\n",
    label="remediation review error import",
)
replace_once(
    Path("vulnhunter/web/remediation_views.py"),
    "        except Exception:\n            review_bundle = None\n",
    "        except RemediationReviewError:\n            review_bundle = None\n",
    label="review receipt exception",
)
replace_once(
    Path("vulnhunter/web/remediation_review_service.py"),
    "import os\nfrom pathlib import Path\n",
    "import os\nimport stat\nfrom pathlib import Path\n",
    label="stat import",
)
replace_once(
    Path("vulnhunter/web/remediation_review_service.py"),
    '''    path = Path(configured).expanduser().resolve()
    try:
        key = path.read_bytes().strip()
    except OSError as exc:
        raise RemediationReviewError(
            "independent remediation review signing key is unavailable"
        ) from exc
''',
    '''    path = Path(configured).expanduser().resolve()
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RemediationReviewError(
                "independent remediation review signing key must be a regular file"
            )
        if metadata.st_mode & 0o077:
            raise RemediationReviewError(
                "independent remediation review signing key must be owner-private"
            )
        key = path.read_bytes().strip()
    except RemediationReviewError:
        raise
    except OSError as exc:
        raise RemediationReviewError(
            "independent remediation review signing key is unavailable"
        ) from exc
''',
    label="owner-private signing key validation",
)
