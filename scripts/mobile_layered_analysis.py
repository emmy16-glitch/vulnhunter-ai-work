"""Run the evidence-first layered Android static analyzer offline."""

from __future__ import annotations

import argparse
from pathlib import Path

from vulnhunter.mobile.layered_analysis import analyze_package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze_package(args.package)
    destination = args.output.expanduser().absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(
        f"{report.artifact_sha256} layers={len(report.completeness.layers)} "
        f"completeness={report.completeness.percentage:.2f}% "
        f"gaps={len(report.gaps)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
