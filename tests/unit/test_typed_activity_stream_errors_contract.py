import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
STREAM_VIEWS = ROOT / "vulnhunter" / "web" / "stream_views.py"


def _source() -> str:
    return STREAM_VIEWS.read_text(encoding="utf-8")


def test_activity_stream_errors_are_typed_and_actionable():
    source = _source()

    for code in (
        "assessment_activity_forbidden",
        "assessment_activity_cursor_invalid",
        "assessment_activity_temporarily_unavailable",
    ):
        assert f'code="{code}"' in source

    assert '"retryable": retryable' in source
    assert '"label": "Try again"' in source
    assert '"url": request.get_full_path()' in source
    assert '"label": "Return to assessment history"' in source
    assert 'reverse("web-scan-run-list")' in source
    assert '"assessment_id"] = run_id' in source


def test_unavailable_activity_preserves_saved_work_and_allows_scoped_retry():
    source = _source()

    assert "Your saved assessment data has not been discarded." in source
    assert "assessment service unavailable" not in source
    assert "temporarily unavailable" in source
    assert "retryable=True" in source


def test_forbidden_and_invalid_cursor_errors_do_not_offer_retry():
    source = _source()

    forbidden = source.index('code="assessment_activity_forbidden"')
    invalid = source.index('code="assessment_activity_cursor_invalid"')
    unavailable = source.index('code="assessment_activity_temporarily_unavailable"')

    assert "retryable=False" in source[forbidden:invalid]
    assert "retryable=False" in source[invalid:unavailable]
