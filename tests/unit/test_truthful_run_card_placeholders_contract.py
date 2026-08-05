import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "vulnhunter" / "web" / "templates" / "web" / "conversation.html"


def _template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def test_new_run_card_does_not_fabricate_zero_counts_or_pending_states():
    template = _template()

    assert 'data-summary-findings aria-label="Finding count unavailable">—<' in template
    assert 'data-summary-evidence aria-label="Evidence count unavailable">—<' in template
    assert "data-summary-approval>Not available<" in template
    assert 'data-progress-count aria-label="Activity count unavailable">—<' in template
    assert 'data-findings-count aria-label="Finding count unavailable">—<' in template
    assert 'data-evidence-count aria-label="Evidence count unavailable">—<' in template
    assert "data-verification-state>Not available<" in template
    assert 'data-audit-count aria-label="Audit event count unavailable">—<' in template

    for misleading_default in (
        "data-summary-findings>0<",
        "data-summary-evidence>0<",
        "data-summary-approval>Pending<",
        "data-progress-count>0 events<",
        "data-findings-count>0<",
        "data-evidence-count>0<",
        "data-verification-state>Pending<",
        "data-audit-count>0 events<",
    ):
        assert misleading_default not in template
