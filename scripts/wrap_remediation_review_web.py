from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected one formatting target in {path}, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    Path("vulnhunter/web/remediation_conversation_state.py"),
    '                "review workspace; governance authentication and checklist authority stay outside chat."\n',
    '                "review workspace; governance authentication and checklist authority stay "\n'
    '                "outside chat."\n',
)
replace_once(
    Path("vulnhunter/web/remediation_conversation_state.py"),
    '                "The signed reviewer decision requires bounded remediation rework. The prior review "\n',
    '                "The signed reviewer decision requires bounded remediation rework. The prior "\n'
    '                "review "\n',
)
replace_once(
    Path("vulnhunter/web/remediation_review_views.py"),
    '                    f"Independent review returned {bundle.outcome.value}; report generation remains "\n',
    '                    f"Independent review returned {bundle.outcome.value}; report generation "\n'
    '                    "remains "\n',
)
