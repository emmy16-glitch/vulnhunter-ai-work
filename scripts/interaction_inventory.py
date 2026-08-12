from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
BASE = ROOT / "vulnhunter" / "web" / "templates" / "web" / "base.html"

_RETIRED_OWNERS = ("workspace-polish.css", "workspace-final-fixes.css", "product-wide.css")
_REQUIRED_SHELL_OWNERS = (
    "tokens.css",
    "app.css",
    "product.css",
    "chat-shell.css",
    "premium-interaction.js",
)
_FORBIDDEN_GLOBAL_OWNERS = ("workspace.css", "premium-interaction.css")


def _read(paths: Iterable[Path]) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def _count(pattern: str, text: str, *, flags: int = 0) -> int:
    return len(re.findall(pattern, text, flags))


def collect_inventory(root: Path = ROOT) -> dict[str, object]:
    static = root / "vulnhunter" / "web" / "static" / "web"
    base_path = root / "vulnhunter" / "web" / "templates" / "web" / "base.html"
    css_paths = sorted(static.glob("*.css"))
    js_paths = sorted(static.glob("*.js"))
    css = _read(css_paths)
    javascript = _read(js_paths)
    base = base_path.read_text(encoding="utf-8")

    metrics = {
        "css_files": len(css_paths),
        "js_files": len(js_paths),
        "transition_declarations": _count(r"\btransition(?:-[\w-]+)?\s*:", css),
        "animation_declarations": _count(r"\banimation(?:-[\w-]+)?\s*:", css),
        "keyframes": _count(r"@keyframes\s+[\w-]+", css),
        "reduced_motion_blocks": _count(
            r"@media\s*\(\s*prefers-reduced-motion\s*:\s*reduce\s*\)", css
        ),
        "timeouts": _count(r"\bsetTimeout\s*\(", javascript),
        "intervals": _count(r"\bsetInterval\s*\(", javascript),
        "animation_frames": _count(r"\brequestAnimationFrame\s*\(", javascript),
        "native_dialog_opens": _count(r"\.showModal\s*\(", javascript),
        "event_streams": _count(r"\bEventSource\s*\(", javascript),
        "loading_markers": _count(r"\b(?:loading|spinner|busy)\b", javascript, flags=re.I),
        "progress_markers": _count(r"\bprogress\b", css + "\n" + javascript, flags=re.I),
    }
    shell_owners = {name: (name in base) for name in _REQUIRED_SHELL_OWNERS}
    forbidden_loaded = [name for name in _FORBIDDEN_GLOBAL_OWNERS if name in base]
    retired_loaded = [name for name in _RETIRED_OWNERS if name in base]
    retired_present = [name for name in _RETIRED_OWNERS if (static / name).exists()]

    return {
        "scope": "repository-static-interaction-baseline",
        "metrics": metrics,
        "shell_owners": shell_owners,
        "forbidden_global_owners": forbidden_loaded,
        "retired_loaded": retired_loaded,
        "retired_present": retired_present,
        "limitations": [
            (
                "Counts are static repository evidence, not frame-time or "
                "device-performance measurements."
            ),
            (
                "Chromium automation does not prove physical Android performance "
                "or TalkBack behaviour."
            ),
            (
                "Motion counts do not imply assessment progress, worker progress, "
                "provider health, or completion."
            ),
        ],
    }


def validate_inventory(inventory: dict[str, object]) -> list[str]:
    errors: list[str] = []
    metrics = inventory["metrics"]
    owners = inventory["shell_owners"]
    if not all(owners.values()):
        missing = sorted(name for name, loaded in owners.items() if not loaded)
        errors.append(f"missing shared interaction owner(s): {', '.join(missing)}")
    if inventory["forbidden_global_owners"]:
        loaded = ", ".join(sorted(inventory["forbidden_global_owners"]))
        errors.append(f"retired competing global owner(s) loaded: {loaded}")
    if inventory["retired_loaded"] or inventory["retired_present"]:
        errors.append("retired workspace correction layers must remain absent")
    if metrics["reduced_motion_blocks"] < 1:
        errors.append("at least one reduced-motion semantic alternative is required")
    if metrics["transition_declarations"] + metrics["animation_declarations"] < 1:
        errors.append("no interaction motion declarations were inventoried")
    if metrics["animation_frames"] < 1:
        errors.append("no requestAnimationFrame interaction scheduling was inventoried")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Measure the repository-owned web interaction surface without claiming device evidence."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when baseline ownership invariants regress",
    )
    args = parser.parse_args()

    inventory = collect_inventory()
    print(json.dumps(inventory, indent=2, sort_keys=True))
    errors = validate_inventory(inventory)
    if args.check and errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
