"""Read-only local CLI for the operational product application layer."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from vulnhunter.product.service import ProductApplicationService, ProductPaths


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulnhunter.product",
        description="Inspect the operational VulnHunter product read models.",
    )
    parser.add_argument("--authorization-database", type=Path, default=Path("authorizations.db"))
    parser.add_argument("--governance-database", type=Path, default=Path("governance.db"))
    parser.add_argument("--agent-database", type=Path, default=Path("agent.db"))
    parser.add_argument("--role-registry-root", type=Path, default=Path("config/roles"))
    parser.add_argument(
        "--runtime-config", type=Path, default=Path("config/agent_runtime/runtime.json")
    )
    parser.add_argument("--product-spec-root", type=Path, default=Path("config/product_interface"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("dashboard")
    subparsers.add_parser("campaigns")
    campaign = subparsers.add_parser("campaign")
    campaign.add_argument("campaign_id")
    subparsers.add_parser("roles")
    role = subparsers.add_parser("role")
    role.add_argument("role_id")
    subparsers.add_parser("skills")
    skill = subparsers.add_parser("skill")
    skill.add_argument("skill_id")
    subparsers.add_parser("runs")
    run = subparsers.add_parser("run")
    run.add_argument("run_id")
    return parser


def _service(args: argparse.Namespace) -> ProductApplicationService:
    return ProductApplicationService(
        ProductPaths(
            authorization_database=args.authorization_database,
            governance_database=args.governance_database,
            agent_database=args.agent_database,
            role_registry_root=args.role_registry_root,
            runtime_config=args.runtime_config,
            product_spec_root=args.product_spec_root,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    service = _service(args)

    if args.command == "status":
        payload = service.load_status().model_dump(mode="json")
    elif args.command == "dashboard":
        payload = service.load_dashboard().model_dump(mode="json")
    elif args.command == "campaigns":
        payload = [item.model_dump(mode="json") for item in service.list_campaigns()]
    elif args.command == "campaign":
        payload = service.get_campaign(args.campaign_id).model_dump(mode="json")
    elif args.command == "roles":
        payload = [item.model_dump(mode="json") for item in service.list_roles()]
    elif args.command == "role":
        payload = service.get_role(args.role_id).model_dump(mode="json")
    elif args.command == "skills":
        payload = [item.model_dump(mode="json") for item in service.list_skills()]
    elif args.command == "skill":
        payload = service.get_skill(args.skill_id).model_dump(mode="json")
    elif args.command == "runs":
        payload = [item.model_dump(mode="json") for item in service.list_agent_runs()]
    elif args.command == "run":
        payload = service.get_agent_run(args.run_id).model_dump(mode="json")
    else:
        parser.error(f"Unsupported command: {args.command}")
        return 2

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0
