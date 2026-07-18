from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tests/unit/test_milestone32_worker_pilot.py"
OLD = """    script.write_text(
        f"#!/usr/bin/env python3\\nimport json\\nprint(json.dumps({payload!r}))\\n",
        encoding="utf-8",
    )
"""
NEW = """    output = json.dumps(payload, separators=(",", ":"))
    script.write_text(
        "#!/bin/sh\\n" + "printf '%s\\n' " + json.dumps(output) + "\\n",
        encoding="utf-8",
    )
"""
text = PATH.read_text(encoding="utf-8")
if OLD not in text:
    raise RuntimeError("fake Nuclei test block changed unexpectedly")
PATH.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
