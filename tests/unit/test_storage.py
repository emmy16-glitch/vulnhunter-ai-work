from datetime import UTC, datetime

from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository


def make_result():
    observation = Observation.create(
        category="missing_security_headers",
        severity="medium",
        title="Missing headers",
        description="Review configuration",
        url="http://127.0.0.1:8000/app/?access_token=secret",
        evidence={"missing_headers": ["Content-Security-Policy"]},
    )
    now = datetime.now(UTC)
    return MappingResult(
        target_url="http://127.0.0.1:8000/app/",
        started_at=now,
        completed_at=now,
        pages=(
            MappedPage(
                url="http://127.0.0.1:8000/app/?access_token=secret",
                depth=0,
                status_code=200,
                content_type="text/html",
                response_bytes=10,
                elapsed_ms=1,
            ),
        ),
        observations=(observation,),
        discovered_urls=1,
        rejected_links=0,
    )


def test_repository_persists_and_lists_scan(tmp_path):
    repo = ScanRepository.from_path(tmp_path / "vh.db")
    repo.initialize()
    scan_id = repo.create_scan("http://127.0.0.1:8000/app/")
    repo.complete_scan(scan_id, make_result())
    scans = repo.list_scans()
    assert scans[0].status == "completed"
    assert scans[0].pages_visited == 1
    assert scans[0].observations_count == 1


def test_repository_redacts_urls_and_labels_observation(tmp_path):
    repo = ScanRepository.from_path(tmp_path / "vh.db")
    repo.initialize()
    scan_id = repo.create_scan("http://127.0.0.1:8000/app/")
    repo.complete_scan(scan_id, make_result())
    observation = repo.list_observations(scan_id=scan_id)[0]
    assert "secret" not in observation.url
    labelled = repo.label_observation(observation.id, "confirmed", note="Checked manually")
    assert labelled.review_label == "confirmed"
    assert labelled.review_note == "Checked manually"
    assert labelled.reviewed_at is not None


def test_repository_marks_failed_scan(tmp_path):
    repo = ScanRepository.from_path(tmp_path / "vh.db")
    repo.initialize()
    scan_id = repo.create_scan("http://127.0.0.1:8000/app/")
    repo.fail_scan(scan_id, "Authorization: Bearer top-secret")
    scan = repo.list_scans()[0]
    assert scan.status == "failed"
    assert "top-secret" not in (scan.error_message or "")
