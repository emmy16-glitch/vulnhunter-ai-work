#!/usr/bin/env python3
"""Write an owner-private MobSF API key and loopback service policy."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import tempfile
from pathlib import Path

_IMAGE = "opensecurity/mobile-security-framework-mobsf:v4.4.6"


def _atomic_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--api-key-file", type=Path, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8008")
    parser.add_argument("--api-key")
    args = parser.parse_args()

    api_key = args.api_key or getpass.getpass("MobSF REST API key: ").strip()
    if not 16 <= len(api_key) <= 512 or any(character.isspace() for character in api_key):
        raise SystemExit("MobSF API key must be 16-512 non-whitespace characters")

    key_file = args.api_key_file.expanduser().absolute()
    policy_file = args.policy.expanduser().absolute()
    _atomic_private(key_file, api_key)
    payload = {
        "schema_version": "1.0",
        "enabled": True,
        "base_url": args.base_url,
        "api_key_file": str(key_file),
        "auth_header": "X-Mobsf-Api-Key",
        "timeout_seconds": 900,
        "maximum_response_bytes": 25_000_000,
        "image": _IMAGE,
        "private_service_only": True,
    }
    _atomic_private(
        policy_file,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )
    print(f"MobSF policy written to {policy_file}")
    print(f"MobSF API key stored owner-only at {key_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
