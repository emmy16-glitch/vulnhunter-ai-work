from pathlib import Path

path = Path("vulnhunter/findings/service.py")
text = path.read_text(encoding="utf-8")
old = (
    "            not in {RemediationState.READY_FOR_IMPLEMENTATION, "
    "RemediationState.NEEDS_REWORK}\n"
)
new = (
    "            not in {\n"
    "                RemediationState.READY_FOR_IMPLEMENTATION,\n"
    "                RemediationState.NEEDS_REWORK,\n"
    "                RemediationState.REVIEW_NEEDS_REWORK,\n"
    "            }\n"
)
if text.count(old) != 2:
    raise SystemExit(f"Expected two remediation state guards, found {text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
