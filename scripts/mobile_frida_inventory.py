#!/usr/bin/env python3
"""Collect a bounded Frida runtime inventory from one approved Android package."""

from __future__ import annotations

import argparse
import json
import re
import time
from typing import Any

import frida

_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
_MAX_MODULES = 512
_MAX_CLASSES = 2_000
_SCRIPT = r"""
'use strict';
const result = {
  modules: Process.enumerateModules().slice(0, 512).map((module) => ({
    name: module.name,
    base: module.base.toString(),
    size: module.size,
    path: module.path
  })),
  java_available: Java.available
};
if (Java.available) {
  Java.perform(() => {
    result.loaded_classes = Java.enumerateLoadedClassesSync().slice(0, 2000);
    send(result);
  });
} else {
  result.loaded_classes = [];
  send(result);
}
"""


def _bounded_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {"modules": [], "loaded_classes": [], "java_available": False}
    raw_modules = payload.get("modules")
    modules: list[dict[str, object]] = []
    if isinstance(raw_modules, list):
        for raw in raw_modules[:_MAX_MODULES]:
            if not isinstance(raw, dict):
                continue
            modules.append(
                {
                    "name": str(raw.get("name") or "")[:255],
                    "base": str(raw.get("base") or "")[:64],
                    "size": max(0, int(raw.get("size") or 0)),
                    "path": str(raw.get("path") or "")[:1_024],
                }
            )
    raw_classes = payload.get("loaded_classes")
    classes = (
        [str(item)[:512] for item in raw_classes[:_MAX_CLASSES]]
        if isinstance(raw_classes, list)
        else []
    )
    return {
        "modules": modules,
        "loaded_classes": classes,
        "java_available": bool(payload.get("java_available")),
    }


def inventory(device_id: str, package_name: str, *, timeout_seconds: int) -> dict[str, object]:
    messages: list[dict[str, object]] = []
    errors: list[str] = []

    def on_message(message: dict[str, Any], data: bytes | None) -> None:
        if message.get("type") == "send":
            messages.append(_bounded_payload(message.get("payload")))
        elif message.get("type") == "error":
            errors.append(str(message.get("description") or "Frida script error")[:500])

    device = frida.get_device(device_id, timeout=timeout_seconds)
    session = device.attach(package_name)
    script = session.create_script(_SCRIPT)
    script.on("message", on_message)
    try:
        script.load()
        deadline = time.monotonic() + timeout_seconds
        while not messages and not errors and time.monotonic() < deadline:
            time.sleep(0.1)
    finally:
        try:
            script.unload()
        finally:
            session.detach()
    if errors:
        raise RuntimeError(errors[0])
    if not messages:
        raise RuntimeError("Frida inventory timed out before receiving a result")
    payload = messages[0]
    return {
        "schema_version": "1.0",
        "frida_version": frida.__version__,
        "device_id": device_id,
        "package_name": package_name,
        **payload,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    args = parser.parse_args()
    if _PACKAGE.fullmatch(args.package) is None:
        raise SystemExit("Android package name is invalid")
    if not 5 <= args.timeout_seconds <= 120:
        raise SystemExit("timeout must be between 5 and 120 seconds")
    result = inventory(
        args.device_id,
        args.package,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
