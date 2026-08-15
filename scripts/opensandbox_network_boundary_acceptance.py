"""Prove that OpenSandbox dns+nft permits one IPv4 target and blocks another reachable IP."""

from __future__ import annotations

import argparse
import json
from datetime import timedelta

_PROBE = r'''
import json
import socket
from pathlib import Path

payload = json.loads(Path("/tmp/vulnhunter-network-probe/plan.json").read_text())

def connect(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            return True
    except OSError:
        return False

receipt = {
    "approved_reachable": connect(payload["approved_host"], payload["approved_port"]),
    "denied_reachable": connect(payload["denied_host"], payload["denied_port"]),
}
Path("/tmp/vulnhunter-network-probe/receipt.json").write_text(
    json.dumps(receipt, sort_keys=True), encoding="utf-8"
)
'''


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--approved-host", required=True)
    parser.add_argument("--approved-port", type=int, required=True)
    parser.add_argument("--denied-host", required=True)
    parser.add_argument("--denied-port", type=int, required=True)
    parser.add_argument("--domain", default="127.0.0.1:8080")
    parser.add_argument("--protocol", choices=("http", "https"), default="http")
    return parser


def main() -> None:
    args = _parser().parse_args()
    from opensandbox import SandboxSync
    from opensandbox.config import ConnectionConfigSync
    from opensandbox.models.execd import RunCommandOpts
    from opensandbox.models.filesystem import WriteEntry
    from opensandbox.models.sandboxes import NetworkPolicy, NetworkRule

    connection = ConnectionConfigSync(
        domain=args.domain,
        protocol=args.protocol,
        request_timeout=timedelta(seconds=30),
        use_server_proxy=True,
    )
    sandbox = SandboxSync.create(
        args.image,
        connection_config=connection,
        timeout=timedelta(seconds=120),
        ready_timeout=timedelta(seconds=45),
        resource={"cpu": "1", "memory": "512Mi"},
        network_policy=NetworkPolicy(
            defaultAction="deny",
            egress=[NetworkRule(action="allow", target=args.approved_host)],
        ),
        metadata={"project": "vulnhunter", "purpose": "network-boundary-acceptance"},
        env={},
    )
    try:
        root = "/tmp/vulnhunter-network-probe"
        sandbox.files.create_directories([WriteEntry(path=root, mode=777)])
        sandbox.files.write_file(f"{root}/network_probe.py", _PROBE, mode=555)
        sandbox.files.write_file(
            f"{root}/plan.json",
            json.dumps(
                {
                    "approved_host": args.approved_host,
                    "approved_port": args.approved_port,
                    "denied_host": args.denied_host,
                    "denied_port": args.denied_port,
                },
                sort_keys=True,
            ),
            mode=444,
        )
        execution = sandbox.commands.run(
            f"python3 {root}/network_probe.py",
            opts=RunCommandOpts(
                working_directory=root,
                timeout=timedelta(seconds=15),
                uid=65532,
                gid=65532,
            ),
        )
        if execution.exit_code != 0:
            detail = execution.error.value if execution.error is not None else execution.exit_code
            raise RuntimeError(f"network boundary probe failed to execute: {detail}")
        receipt = json.loads(sandbox.files.read_text(f"{root}/receipt.json"))
    finally:
        sandbox.destroy()

    if receipt.get("approved_reachable") is not True:
        raise RuntimeError("OpenSandbox exact-IP policy blocked the approved target")
    if receipt.get("denied_reachable") is not False:
        raise RuntimeError("OpenSandbox exact-IP policy allowed an undeclared destination")
    receipt.update(
        {
            "status": "accepted",
            "approved_host": args.approved_host,
            "approved_port": args.approved_port,
            "denied_host": args.denied_host,
            "denied_port": args.denied_port,
        }
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
