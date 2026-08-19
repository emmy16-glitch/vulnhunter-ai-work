"""Reconstruct an Android package set without installing or executing it."""

from __future__ import annotations

import argparse
from pathlib import Path

from vulnhunter.mobile.package_sets import reconstruct_package_set


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = reconstruct_package_set(args.source)
    destination = args.output.expanduser().absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(
        f"{result.set_id} package={result.package_name or 'unknown'} "
        f"members={len(result.members)} complete={result.complete} gaps={len(result.gaps)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
