"""Minimal worker-owned Obscura MCP runtime adapter.

The adapter is deliberately narrow: VulnHunter sends typed, policy-checked
BrowserAction values and the adapter maps them to an allowlisted MCP tool.
The model never receives a raw MCP client or an arbitrary command path.
"""

from __future__ import annotations

import base64
import json
import os
import selectors
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import (
    BrowserAction,
    BrowserActionType,
    BrowserRuntimeCapabilities,
    BrowserRuntimeName,
)


class ObscuraRuntimeError(RuntimeError):
    """Raised when Obscura cannot start, respond, or clean up safely."""


@dataclass(frozen=True)
class ObscuraRuntimeConfig:
    binary: Path
    expected_version: str = "0.2.0"
    archive_sha256: str = "d601f4f542319c3b9fa8dca9f5ccfc134a2ca001648da528db5f03c9e6c2599b"
    startup_timeout_seconds: float = 8.0
    action_timeout_seconds: float = 30.0
    idle_timeout_seconds: float = 120.0
    maximum_response_bytes: int = 4_000_000
    allow_private_network: bool = False

    def __post_init__(self) -> None:
        if self.startup_timeout_seconds <= 0 or self.action_timeout_seconds <= 0:
            raise ValueError("Obscura timeouts must be positive")
        if self.idle_timeout_seconds < self.action_timeout_seconds:
            raise ValueError("Obscura idle timeout must cover one action timeout")
        if len(self.archive_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in self.archive_sha256
        ):
            raise ValueError("Obscura archive SHA-256 is malformed")
        if not self.expected_version or any(c.isspace() for c in self.expected_version):
            raise ValueError("Obscura expected version is malformed")


class ObscuraMcpProcess:
    """One short-lived stdio MCP process owned by a worker/session."""

    def __init__(self, config: ObscuraRuntimeConfig) -> None:
        self.config = config
        self.process: subprocess.Popen[bytes] | None = None
        self.request_id = 0
        self.last_activity = 0.0
        self.capabilities: BrowserRuntimeCapabilities | None = None
        self._tools: dict[str, Mapping[str, Any]] = {}

    def start(self) -> BrowserRuntimeCapabilities:
        if self.process is not None:
            return self.capabilities or self._capabilities(False, "process already started")
        binary = self.config.binary.expanduser().resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ObscuraRuntimeError("Obscura binary is unavailable or not executable")
        try:
            command = [str(binary)]
            if self.config.allow_private_network:
                command.append("--allow-private-network")
            command.append("mcp")
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            raise ObscuraRuntimeError("Obscura process could not start") from exc
        self.process = process
        self.last_activity = time.monotonic()
        try:
            initialize = self._request(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "vulnhunter-browser-worker", "version": "1.0"},
                },
            )
            if initialize.get("protocolVersion") != "2024-11-05":
                raise ObscuraRuntimeError("Obscura MCP protocol version is unsupported")
            self._notify("notifications/initialized", {})
            listing = self._request("tools/list", {})
            tools = listing.get("tools")
            if not isinstance(tools, list):
                raise ObscuraRuntimeError("Obscura MCP tool catalog is invalid")
            self._tools = {
                str(tool.get("name")): tool
                for tool in tools
                if isinstance(tool, dict) and isinstance(tool.get("name"), str)
            }
            required = {
                "browser_navigate",
                "browser_snapshot",
                "browser_interactive_elements",
                "browser_detect_forms",
                "browser_click",
                "browser_fill",
                "browser_type",
                "browser_press_key",
                "browser_select_option",
                "browser_scroll",
                "browser_wait_for_text",
                "browser_network_requests",
                "browser_console_messages",
                "browser_screenshot",
            }
            missing = sorted(required - self._tools.keys())
            if missing:
                raise ObscuraRuntimeError(
                    "Obscura MCP is missing required tools: " + ", ".join(missing)
                )
            version = self._read_version(binary)
            if version != self.config.expected_version:
                raise ObscuraRuntimeError(
                    "Obscura version mismatch: "
                    f"expected {self.config.expected_version}, got {version}"
                )
            self.capabilities = self._capabilities(True, "preflight passed", version=version)
            return self.capabilities
        except Exception:
            self.close()
            raise

    def call(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.process is None:
            raise ObscuraRuntimeError("Obscura process is not started")
        if tool_name not in self._tools:
            raise ObscuraRuntimeError(f"Obscura tool is not allowlisted: {tool_name}")
        result = self._request("tools/call", {"name": tool_name, "arguments": dict(arguments)})
        return _normalize_tool_result(result)

    def execute(self, action: BrowserAction) -> dict[str, Any]:
        tool, arguments = _action_to_tool(action)
        if tool is None:
            if action.action_type == BrowserActionType.WAIT:
                seconds = float(action.parameters.get("seconds", 0))
                time.sleep(seconds)
                return {"summary": f"waited {seconds:g} seconds"}
            raise ObscuraRuntimeError(
                f"browser action is not implemented: {action.action_type.value}"
            )
        return self.call(tool, arguments)

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        try:
            if process.poll() is None and "browser_close" in self._tools:
                self._request("tools/call", {"name": "browser_close", "arguments": {}})
        except Exception:
            pass
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.terminate()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        finally:
            try:
                if process.stdout is not None:
                    process.stdout.close()
            except OSError:
                pass

    def _request(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": dict(params),
        }
        self._write(request)
        response = self._read_response()
        if response.get("error") is not None:
            error = response.get("error")
            raise ObscuraRuntimeError(f"Obscura MCP error: {str(error)[:400]}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise ObscuraRuntimeError("Obscura MCP result is not an object")
        return result

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def _write(self, payload: Mapping[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None:
            raise ObscuraRuntimeError("Obscura process input is unavailable")
        raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            process.stdin.write(raw)
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ObscuraRuntimeError("Obscura MCP process exited while writing") from exc
        self.last_activity = time.monotonic()

    def _read_response(self) -> dict[str, Any]:
        process = self.process
        if process is None or process.stdout is None:
            raise ObscuraRuntimeError("Obscura process output is unavailable")
        selector = selectors.DefaultSelector()
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            events = selector.select(timeout=self.config.action_timeout_seconds)
            if not events:
                raise ObscuraRuntimeError("Obscura MCP response timed out")
            line = process.stdout.readline(self.config.maximum_response_bytes + 1)
        finally:
            selector.close()
        if not line:
            raise ObscuraRuntimeError("Obscura MCP process exited without a response")
        if len(line) > self.config.maximum_response_bytes:
            raise ObscuraRuntimeError("Obscura MCP response exceeded the bounded size")
        try:
            response = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ObscuraRuntimeError("Obscura MCP response is not valid JSON") from exc
        if not isinstance(response, dict):
            raise ObscuraRuntimeError("Obscura MCP response is not an object")
        self.last_activity = time.monotonic()
        return response

    def _read_version(self, binary: Path) -> str:
        try:
            result = subprocess.run(
                [str(binary), "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
                env={"PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ObscuraRuntimeError("Obscura version check failed") from exc
        value = result.stdout.strip().split()
        if len(value) != 2 or value[0] != "obscura":
            raise ObscuraRuntimeError("Obscura version output is invalid")
        return value[1]

    def _capabilities(
        self, passed: bool, reason: str, *, version: str | None = None
    ) -> BrowserRuntimeCapabilities:
        return BrowserRuntimeCapabilities(
            runtime=BrowserRuntimeName.OBSCURA,
            version=version or self.config.expected_version,
            mcp_available=passed,
            screenshot_available=passed,
            network_available=passed,
            console_available=passed,
            forms_available=passed,
            interactive_elements_available=passed,
            evaluate_available=False,
            preflight_passed=passed,
            reason=reason,
        )


def _action_to_tool(action: BrowserAction) -> tuple[str | None, dict[str, Any]]:
    values = dict(action.parameters)
    mapping: dict[BrowserActionType, tuple[str, tuple[str, ...]]] = {
        BrowserActionType.NAVIGATE: ("browser_navigate", ("url", "waitUntil", "timeout")),
        BrowserActionType.SNAPSHOT: ("browser_snapshot", ("max_chars",)),
        BrowserActionType.GET_LINKS: ("browser_links", ("limit",)),
        BrowserActionType.GET_INTERACTIVE_ELEMENTS: ("browser_interactive_elements", ("limit",)),
        BrowserActionType.DETECT_FORMS: ("browser_detect_forms", ("limit",)),
        BrowserActionType.GET_ATTRIBUTE: (
            "browser_get_attribute",
            ("ref", "selector", "attribute"),
        ),
        BrowserActionType.COUNT: ("browser_count", ("selector",)),
        BrowserActionType.SEARCH_TEXT: (
            "browser_search",
            ("query", "case_sensitive", "limit", "context_chars"),
        ),
        BrowserActionType.CLICK: ("browser_click", ("ref", "selector")),
        BrowserActionType.FILL: ("browser_fill", ("ref", "selector", "value")),
        BrowserActionType.TYPE: ("browser_type", ("ref", "selector", "text")),
        BrowserActionType.PRESS_KEY: ("browser_press_key", ("key", "ref", "selector")),
        BrowserActionType.SELECT_OPTION: ("browser_select_option", ("selector", "value", "label")),
        BrowserActionType.SCROLL: ("browser_scroll", ("direction", "amount", "ref", "selector")),
        BrowserActionType.WAIT_FOR_TEXT: ("browser_wait_for_text", ("text", "timeout")),
        BrowserActionType.GET_NETWORK_REQUESTS: ("browser_network_requests", ()),
        BrowserActionType.GET_CONSOLE_MESSAGES: ("browser_console_messages", ()),
        BrowserActionType.TAKE_SCREENSHOT: ("browser_screenshot", ("width", "height")),
    }
    if action.action_type == BrowserActionType.READ_PAGE:
        return "browser_snapshot", {"max_chars": int(values.get("max_chars", 4_000))}
    if action.action_type == BrowserActionType.GET_CURRENT_URL:
        return "browser_snapshot", {"max_chars": 0}
    item = mapping.get(action.action_type)
    if item is None:
        return None, {}
    tool, keys = item
    return tool, {key: values[key] for key in keys if key in values}


def _normalize_tool_result(result: Mapping[str, Any]) -> dict[str, Any]:
    content = result.get("content")
    normalized: dict[str, Any] = {}
    if isinstance(result.get("structuredContent"), dict):
        normalized.update(result["structuredContent"])
    if isinstance(content, list):
        texts: list[str] = []
        images: list[bytes] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                texts.append(item["text"])
            elif item.get("type") == "image" and isinstance(item.get("data"), str):
                try:
                    images.append(base64.b64decode(item["data"], validate=True))
                except (ValueError, TypeError):
                    continue
        if texts:
            normalized["text"] = "\n".join(texts)
        if images:
            normalized["images"] = images
    for key, value in result.items():
        if key not in {"content", "structuredContent"}:
            normalized[key] = value
    return normalized


__all__ = ["ObscuraMcpProcess", "ObscuraRuntimeConfig", "ObscuraRuntimeError"]
