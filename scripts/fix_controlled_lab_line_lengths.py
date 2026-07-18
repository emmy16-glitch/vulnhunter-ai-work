from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected text missing from {relative}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "vulnhunter/adversary_lab/runner.py",
    '                "result": "Synthetic records reached the approved internal sink with matching hashes."\n',
    '                "result": (\n                    "Synthetic records reached the approved internal sink "\n                    "with matching hashes."\n                )\n',
)
replace_once(
    "vulnhunter/adversary_lab/service.py",
    '                        f"Trial {trial_number} of {plan.maximum_trials}: restoring the clean snapshot."\n',
    '                        f"Trial {trial_number} of {plan.maximum_trials}: "\n                        "restoring the clean snapshot."\n',
)
replace_once(
    "vulnhunter/adversary_lab/service.py",
    '                        f"Trial {trial_number} of {plan.maximum_trials}: restoring the clean snapshot."\n',
    '                        f"Trial {trial_number} of {plan.maximum_trials}: "\n                        "restoring the clean snapshot."\n',
)
replace_once(
    "vulnhunter/adversary_lab/service.py",
    '                summary="The synthetic lab worker completed and the disposable workspace was removed.",\n',
    '                summary=(\n                    "The synthetic lab worker completed and the disposable "\n                    "workspace was removed."\n                ),\n',
)
replace_once(
    "vulnhunter/web/lab_views.py",
    '                "The exact synthetic lab plan was created and is waiting for an independent approver.",\n',
    '                "The exact synthetic lab plan was created and is waiting "\n                "for an independent approver.",\n',
)
