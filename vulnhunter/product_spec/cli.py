"""Read-only CLI for the product-interface blueprint."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from vulnhunter.product_spec.registry import ProductInterfaceSpec, SpecValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m vulnhunter.product_spec")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("config/product_interface"),
        help="Path to the product-interface specification directory.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="Validate all blueprint documents.")
    subparsers.add_parser("fingerprint", help="Print the deterministic SHA-256 fingerprint.")
    subparsers.add_parser("summary", help="Print a machine-readable blueprint summary.")
    subparsers.add_parser("list-pages", help="List page IDs, routes, and titles.")
    show_page = subparsers.add_parser("show-page", help="Print one page definition.")
    show_page.add_argument("page_id")
    subparsers.add_parser("figma-summary", help="Print the Figma handoff summary.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        spec = ProductInterfaceSpec.from_path(args.root)
    except SpecValidationError as exc:
        parser.error(str(exc))

    if args.command == "validate":
        print(json.dumps(spec.summary(), indent=2, sort_keys=True))
        return 0
    if args.command == "fingerprint":
        print(spec.fingerprint())
        return 0
    if args.command == "summary":
        print(json.dumps(spec.summary(), indent=2, sort_keys=True))
        return 0
    if args.command == "list-pages":
        for page in sorted(spec.pages, key=lambda item: item["route"]):
            print(f"{page['page_id']}\t{page['route']}\t{page['title']}")
        return 0
    if args.command == "show-page":
        try:
            page = spec.page(args.page_id)
        except KeyError:
            parser.error(f"Unknown page ID: {args.page_id}")
        print(json.dumps(page, indent=2, sort_keys=True))
        return 0
    if args.command == "figma-summary":
        print(
            json.dumps(
                spec.documents["figma_handoff.json"],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    parser.error(f"Unsupported command: {args.command}")
    return 2
