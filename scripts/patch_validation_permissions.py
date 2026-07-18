from __future__ import annotations

from pathlib import Path

root = Path(__file__).resolve().parents[1]
paths = [root / "vulnhunter/web/lab_views.py", root / "vulnhunter/web/views.py"]
replacements = {
    'required_actions=("lab.read", "scan.read", "audit.read")': 'required_actions=("scan.read", "audit.read")',
    '_operator(request, "lab.request")': '_operator(request, "settings.manage")',
    '"approve": "lab.approve"': '"approve": "campaign.approve"',
    '"execute": "lab.execute"': '"execute": "settings.manage"',
    '"cancel": "lab.cancel"': '"cancel": "settings.manage"',
    '_operator(request, "lab.approve")': '_operator(request, "campaign.approve")',
    '_operator(request, "lab.execute")': '_operator(request, "settings.manage")',
    '_operator(request, "lab.cancel")': '_operator(request, "settings.manage")',
    'required_actions=("lab.request",)': 'required_actions=("settings.manage",)',
}
for path in paths:
    text = path.read_text(encoding="utf-8")
    for old, new in replacements.items():
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
