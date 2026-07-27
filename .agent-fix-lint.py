from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path} but found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


hf = Path("vulnhunter/providers/huggingface.py")
replace_once(
    hf,
    '                else f"Hugging Face request was rejected safely (HTTP {exc.status_code}): {exc.safe_detail}"\n',
    '                else (\n'
    '                    f"Hugging Face request was rejected safely (HTTP {exc.status_code}): "\n'
    '                    f"{exc.safe_detail}"\n'
    '                )\n',
)

service = Path("vulnhunter/web/conversation_service.py")
replacements = (
    (
        '            "assessment state. Use New workspace for another task and History to reopen earlier work."\n',
        '            "assessment state. Use New workspace for another task and History to reopen "\n'
        '            "earlier work."\n',
    ),
    (
        '            "I can show the controlled target for the selected assessment. If this workspace has no "\n',
        '            "I can show the controlled target for the selected assessment. If this workspace "\n'
        '            "has no "\n',
    ),
    (
        '            "Describe the security question, paste an authorised http or https target, or attach an "\n',
        '            "Describe the security question, paste an authorised http or https target, or "\n'
        '            "attach an "\n',
    ),
    (
        '            "I have not lost the workspace context. Add the exact point you want examined next, and "\n',
        '            "I have not lost the workspace context. Add the exact point you want examined "\n'
        '            "next, and "\n',
    ),
    (
        '            "medium": "Analyse the question carefully, connect relevant context, and explain a useful answer.",\n',
        '            "medium": (\n'
        '                "Analyse the question carefully, connect relevant context, and explain a "\n'
        '                "useful answer."\n'
        '            ),\n',
    ),
    (
        '                "available evidence, and give a thorough, non-repetitive answer with concrete next steps."\n',
        '                "available evidence, and give a thorough, non-repetitive answer with "\n'
        '                "concrete next steps."\n',
    ),
    (
        '        "questions, teach concepts, analyse supplied evidence, explain APK and website results, and "\n',
        '        "questions, teach concepts, analyse supplied evidence, explain APK and website "\n'
        '        "results, and "\n',
    ),
    (
        '        "Use the read-only workspace data when relevant and clearly distinguish stored evidence from "\n',
        '        "Use the read-only workspace data when relevant and clearly distinguish stored "\n'
        '        "evidence from "\n',
    ),
    (
        '        "changes scope, approves or cancels actions, executes scanners, verifies findings, sets final "\n',
        '        "changes scope, approves or cancels actions, executes scanners, verifies findings, "\n'
        '        "sets final "\n',
    ),
    (
        '        "severity, or publishes results. Do not reveal hidden chain-of-thought; provide conclusions "\n',
        '        "severity, or publishes results. Do not reveal hidden chain-of-thought; provide "\n'
        '        "conclusions "\n',
    ),
)
for old, new in replacements:
    replace_once(service, old, new)
