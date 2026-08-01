from __future__ import annotations

import subprocess
from pathlib import Path

# Branch-only formatter input; this helper is deleted before merge.
FILES = (
    "tests/unit/test_governed_retest.py",
    "tests/unit/test_governed_retest_web.py",
    "tests/unit/test_remediation_fix_graph_projection.py",
    "tests/unit/test_retest_assessment_graph.py",
    "vulnhunter/assessment_graph/retest.py",
    "vulnhunter/assessment_graph/remediation.py",
    "vulnhunter/findings/models.py",
    "vulnhunter/findings/retest.py",
    "vulnhunter/findings/service.py",
    "vulnhunter/web/retest_assessment_graph.py",
    "vulnhunter/web/retest_conversation_state.py",
    "vulnhunter/web/retest_conversation_views.py",
    "vulnhunter/web/retest_service.py",
    "vulnhunter/web/retest_views.py",
)

state_path = Path("vulnhunter/web/retest_conversation_state.py")
text = state_path.read_text(encoding="utf-8")
old = (
    '                "controlled tools, then submit typed before/after evidence and '
    'deterministic receipts."\n'
)
new = (
    '                "controlled tools, then submit typed before/after evidence and '
    'deterministic "\n'
    '                "receipts."\n'
)
if text.count(old) != 1:
    raise SystemExit("Expected exactly one retest next-step message to wrap")
state_path.write_text(text.replace(old, new), encoding="utf-8")

subprocess.run(("python", "-m", "ruff", "format", *FILES), check=True)
subprocess.run(("python", "-m", "ruff", "check", "--fix", *FILES), check=True)
subprocess.run(("python", "-m", "ruff", "check", *FILES), check=True)
