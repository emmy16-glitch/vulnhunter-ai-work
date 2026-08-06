import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
STREAM_VIEWS = ROOT / "vulnhunter" / "web" / "stream_views.py"
UNIFIED_VIEWS = ROOT / "vulnhunter" / "web" / "unified_assessment_views.py"


def _source(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def test_activity_stream_errors_are_typed_and_actionable():
    source = _source(STREAM_VIEWS)

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
    source = _source(STREAM_VIEWS)

    assert "Your saved assessment data has not been discarded." in source
    assert "assessment service unavailable" not in source
    assert "temporarily unavailable" in source
    assert "retryable=True" in source


def test_forbidden_and_invalid_cursor_errors_do_not_offer_retry():
    source = _source(STREAM_VIEWS)

    forbidden = source.index('code="assessment_activity_forbidden"')
    invalid = source.index('code="assessment_activity_cursor_invalid"')
    unavailable = source.index('code="assessment_activity_temporarily_unavailable"')

    assert "retryable=False" in source[forbidden:invalid]
    assert "retryable=False" in source[invalid:unavailable]


def test_canonical_polling_and_stream_routes_share_typed_recovery_contracts():
    source = _source(UNIFIED_VIEWS)

    assert source.count("stream_views._activity_error(") == 7
    assert source.count('code="assessment_activity_forbidden"') == 2
    assert source.count('code="assessment_activity_cursor_invalid"') == 3
    assert source.count('code="assessment_activity_temporarily_unavailable"') == 2

    assert 'JsonResponse({"detail": "forbidden"}' not in source
    assert 'JsonResponse({"detail": "assessment service unavailable"}' not in source
    assert 'JsonResponse({"detail": str(exc)}' not in source
    assert source.count("Your saved assessment data has not been discarded.") == 2


def test_canonical_activity_errors_preserve_private_not_found_behaviour():
    source = _source(UNIFIED_VIEWS)

    assert source.count('raise Http404("Assessment run does not exist.")') >= 3
    assert source.count("except ProductNotFoundError as exc:") >= 3
    assert source.count("raise Http404(str(exc)) from exc") >= 3
