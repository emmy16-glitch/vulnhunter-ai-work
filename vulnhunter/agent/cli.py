"""CLI for local dry runs and audit inspection of the bounded agent runtime."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from vulnhunter.agent.builtins import build_safe_demo_tools
from vulnhunter.agent.config import load_runtime_config, runtime_config_fingerprint
from vulnhunter.agent.controller import AgentController, AgentRuntime
from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import (
    AgentProposal,
    PermissionManifest,
    ProposalKind,
    ToolCall,
    ToolRisk,
)
from vulnhunter.agent.planner import SequencePlanner
from vulnhunter.agent.store import AgentStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulnhunter.agent",
        description="Run and inspect the bounded VulnHunter agent-runtime foundation.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/agent_runtime/runtime.json"),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate-config")
    demo = subparsers.add_parser("demo")
    demo.add_argument("--database", type=Path, required=True)
    demo.add_argument("--task-id", default="demo-agent-task")
    demo.add_argument("--value", default="bounded execution verified")

    show = subparsers.add_parser("show")
    show.add_argument("--database", type=Path, required=True)
    show.add_argument("task_id")

    verify = subparsers.add_parser("verify-audit")
    verify.add_argument("--database", type=Path, required=True)
    verify.add_argument("task_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = load_runtime_config(args.config)
    if args.command == "validate-config":
        print(
            json.dumps(
                {
                    "runtime": config.model_dump(mode="json"),
                    "fingerprint": runtime_config_fingerprint(config),
                },
                indent=2,
            )
        )
        return 0

    store = AgentStore(args.database)
    if args.command == "demo":
        planner = SequencePlanner(
            (
                AgentProposal(
                    kind=ProposalKind.TOOL,
                    rationale="Inspect the supplied local demo value.",
                    call=ToolCall(
                        tool_id="agent.echo",
                        action="evidence.inspect",
                        operation="echo",
                        arguments={"value": args.value},
                    ),
                ),
                AgentProposal(
                    kind=ProposalKind.COMPLETE,
                    rationale="The approved local tool completed successfully.",
                    final_summary="Bounded local agent demonstration completed.",
                ),
            )
        )
        controller = AgentController(
            AgentRuntime(
                config=config,
                store=store,
                planner=planner,
                tools=build_safe_demo_tools(),
                evaluator=ResultEvaluator(),
            )
        )
        manifest = PermissionManifest(
            manifest_id="demo-permission-manifest",
            role_id="orchestrator",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        )
        controller.create_task(
            task_id=args.task_id,
            objective="Run a safe local bounded-agent demonstration.",
            permission_manifest=manifest,
        )
        controller.run(args.task_id)
        print(json.dumps(controller.report(args.task_id).model_dump(mode="json"), indent=2))
        return 0

    if args.command == "show":
        task = store.get_task(args.task_id)
        events = store.list_events(args.task_id)
        print(
            json.dumps(
                {
                    "task": task.model_dump(mode="json"),
                    "events": [event.model_dump(mode="json") for event in events],
                },
                indent=2,
            )
        )
        return 0

    if args.command == "verify-audit":
        print(store.verify_integrity(args.task_id))
        return 0

    raise AssertionError("unreachable command")
