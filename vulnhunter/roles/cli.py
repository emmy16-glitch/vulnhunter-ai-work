"""Read-only command-line interface for the role and skill registry."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from vulnhunter.roles.models import DecisionStatus
from vulnhunter.roles.registry import RegistryError, RoleRegistry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulnhunter.roles",
        description="Validate and inspect the VulnHunter role and skill registry.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("config/roles"),
        help="Registry root containing registry.json, roles/, and skills/.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate", help="Validate the complete registry snapshot.")
    subparsers.add_parser("fingerprint", help="Print the deterministic registry SHA-256.")
    subparsers.add_parser("list-roles", help="List registered roles.")
    subparsers.add_parser("list-skills", help="List registered skills.")

    show_role = subparsers.add_parser("show-role", help="Print one role as JSON.")
    show_role.add_argument("role_id")

    show_skill = subparsers.add_parser("show-skill", help="Print one skill as JSON.")
    show_skill.add_argument("skill_id")

    check = subparsers.add_parser(
        "check-action",
        help="Evaluate a proposed action against the declaration only.",
    )
    check.add_argument("role_id")
    check.add_argument("action")
    check.add_argument("--tool")
    check.add_argument("--operation")
    check.add_argument("--connector")
    check.add_argument("--approval-reference")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        registry = RoleRegistry.from_path(args.root)

        if args.command == "validate":
            print(json.dumps(registry.validate().model_dump(mode="json"), indent=2))
            return 0
        if args.command == "fingerprint":
            print(registry.fingerprint())
            return 0
        if args.command == "list-roles":
            for role in sorted(registry.roles, key=lambda item: item.role_id):
                print(f"{role.role_id}\t{role.status}\t{role.risk_level}\t{role.display_name}")
            return 0
        if args.command == "list-skills":
            for skill in sorted(registry.skills, key=lambda item: item.skill_id):
                print(f"{skill.skill_id}\t{skill.status}\t{skill.risk_level}\t{skill.display_name}")
            return 0
        if args.command == "show-role":
            print(
                json.dumps(
                    registry.get_role(args.role_id).model_dump(mode="json"),
                    indent=2,
                )
            )
            return 0
        if args.command == "show-skill":
            print(
                json.dumps(
                    registry.get_skill(args.skill_id).model_dump(mode="json"),
                    indent=2,
                )
            )
            return 0
        if args.command == "check-action":
            decision = registry.evaluate_action(
                args.role_id,
                args.action,
                tool_id=args.tool,
                operation=args.operation,
                connector_id=args.connector,
                approval_reference=args.approval_reference,
            )
            print(json.dumps(decision.model_dump(mode="json"), indent=2))
            if decision.status == DecisionStatus.ALLOWED:
                return 0
            if decision.status == DecisionStatus.REQUIRES_APPROVAL:
                return 3
            return 2
    except RegistryError as exc:
        print(f"Registry validation failed: {exc}")
        return 2

    raise AssertionError("unreachable command")
