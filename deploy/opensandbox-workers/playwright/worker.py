"""Passive Playwright collector executed only inside the VulnHunter sandbox."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import sys
import time
from collections import deque
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

_ALLOWED_METHODS = frozenset({"GET", "HEAD"})
_PLAN_FIELDS = {
    "schema_version",
    "target_url",
    "scheme",
    "hostname",
    "port",
    "path_boundary",
    "approved_ip",
    "policy",
}
_POLICY_FIELDS = {
    "maximum_pages",
    "maximum_depth",
    "maximum_requests",
    "maximum_links_per_page",
    "navigation_timeout_ms",
    "settle_time_ms",
    "minimum_request_delay_seconds",
}
_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9_.:-]+")


def _load_plan(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != _PLAN_FIELDS:
        raise ValueError("worker plan fields are invalid")
    if payload.get("schema_version") != 1:
        raise ValueError("worker plan schema is unsupported")
    policy = payload.get("policy")
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        raise ValueError("worker policy fields are invalid")
    return payload


def _decode_path(path: str) -> str:
    decoded = path or "/"
    for _ in range(3):
        updated = unquote(decoded)
        if updated == decoded:
            break
        decoded = updated
    if "\\" in decoded or any(ord(character) < 32 for character in decoded):
        raise ValueError("unsafe URL path")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("unsafe URL path")
    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    if decoded.endswith("/") and normalized != "/" and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _path_within(boundary: str, candidate: str) -> bool:
    root = _decode_path(boundary)
    current = _decode_path(candidate)
    if root == "/":
        return True
    root = root.rstrip("/")
    current = current.rstrip("/") or "/"
    return current == root or current.startswith(root + "/")


def _origin_matches(url: str, plan: dict[str, object]) -> bool:
    try:
        parsed = urlsplit(url)
        if parsed.username is not None or parsed.password is not None:
            return False
        scheme = str(plan["scheme"])
        hostname = str(plan["hostname"])
        port = int(plan["port"])
        effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return (
            parsed.scheme == scheme
            and parsed.hostname is not None
            and parsed.hostname.rstrip(".").casefold() == hostname
            and effective_port == port
            and _path_within(str(plan["path_boundary"]), parsed.path)
        )
    except (TypeError, ValueError):
        return False


def _safe_url(url: str) -> str:
    """Keep origin/path only. Query values and fragments never leave the sandbox."""

    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    display = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port
    netloc = display if port in {None, default_port} else f"{display}:{port}"
    return urlunsplit((parsed.scheme, netloc, _decode_path(parsed.path), "", ""))


def _safe_text(value: object, maximum: int) -> str:
    text = " ".join(str(value or "").split())
    return "".join(character for character in text if ord(character) >= 32)[:maximum]


def _safe_field_name(value: object) -> str:
    return _safe_text(value, 200)


def _safe_input_type(value: object) -> str:
    return _SAFE_TOKEN.sub("", _safe_text(value, 80))[:80]


def _form_sha256(method: str, action_url: str, fields: list[dict[str, object]]) -> str:
    payload = {
        "method": method,
        "action_url": action_url,
        "fields": fields,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


async def _collect(plan: dict[str, object]) -> dict[str, object]:
    policy = dict(plan["policy"])
    maximum_pages = int(policy["maximum_pages"])
    maximum_depth = int(policy["maximum_depth"])
    maximum_requests = int(policy["maximum_requests"])
    maximum_links = int(policy["maximum_links_per_page"])
    navigation_timeout_ms = int(policy["navigation_timeout_ms"])
    settle_time_ms = int(policy["settle_time_ms"])
    minimum_delay = float(policy["minimum_request_delay_seconds"])

    counters = {
        "allowed_requests": 0,
        "blocked_external_requests": 0,
        "blocked_mutating_requests": 0,
        "blocked_websockets": 0,
    }
    budget_exhausted = False
    request_lock = asyncio.Lock()
    last_request_at = 0.0
    active_requests: list[dict[str, object]] = []

    async with async_playwright() as playwright:
        launch_args = ["--disable-background-networking"]
        hostname = str(plan["hostname"])
        approved_ip = str(plan["approved_ip"])
        try:
            is_literal = hostname == str(ipaddress.ip_address(hostname))
        except ValueError:
            is_literal = False
        if not is_literal:
            launch_args.append(
                f"--host-resolver-rules=MAP {hostname} {approved_ip},EXCLUDE localhost"
            )

        browser = await playwright.chromium.launch(
            headless=True,
            # Chromium's nested Linux namespace sandbox cannot initialize under the outer
            # OpenSandbox/Docker no-new-privileges profile. Keep it disabled and rely on the
            # mandatory outer non-root/cap-drop/exact-egress sandbox boundary.
            chromium_sandbox=False,
            args=launch_args,
        )
        context = await browser.new_context(
            accept_downloads=False,
            service_workers="block",
        )
        context.set_default_timeout(navigation_timeout_ms)

        async def handle_websocket(web_socket) -> None:
            counters["blocked_websockets"] += 1
            await web_socket.close(
                code=1008,
                reason="VulnHunter passive perception blocks WebSockets",
            )

        await context.route_web_socket("**/*", handle_websocket)

        async def handle_route(route, request) -> None:
            nonlocal budget_exhausted, last_request_at
            method = request.method.upper()
            if method not in _ALLOWED_METHODS:
                counters["blocked_mutating_requests"] += 1
                await route.abort("blockedbyclient")
                return
            if not _origin_matches(request.url, plan):
                counters["blocked_external_requests"] += 1
                await route.abort("blockedbyclient")
                return

            async with request_lock:
                if counters["allowed_requests"] >= maximum_requests:
                    budget_exhausted = True
                    await route.abort("blockedbyclient")
                    return
                wait = minimum_delay - (time.monotonic() - last_request_at)
                if wait > 0:
                    await asyncio.sleep(wait)
                counters["allowed_requests"] += 1
                last_request_at = time.monotonic()
                active_requests.append(
                    {
                        "method": method,
                        "url": _safe_url(request.url),
                        "resource_type": _safe_text(request.resource_type, 80),
                        "status_code": None,
                    }
                )
            await route.continue_()

        await context.route("**/*", handle_route)

        async def record_response(response) -> None:
            method = response.request.method.upper()
            if method not in _ALLOWED_METHODS or not _origin_matches(response.url, plan):
                return
            safe_url = _safe_url(response.url)
            resource_type = _safe_text(response.request.resource_type, 80)
            for item in reversed(active_requests):
                if (
                    item["method"] == method
                    and item["url"] == safe_url
                    and item["resource_type"] == resource_type
                    and item["status_code"] is None
                ):
                    item["status_code"] = response.status
                    return

        page = await context.new_page()
        page.on("response", lambda response: asyncio.create_task(record_response(response)))

        start_url = _safe_url(str(plan["target_url"]))
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        queued = {start_url}
        visited: set[str] = set()
        pages: list[dict[str, object]] = []

        while queue and len(pages) < maximum_pages and not budget_exhausted:
            url, depth = queue.popleft()
            if url in visited or not _origin_matches(url, plan):
                continue

            active_requests.clear()
            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=navigation_timeout_ms,
                )
                if settle_time_ms:
                    await page.wait_for_timeout(settle_time_ms)
            except (PlaywrightTimeoutError, PlaywrightError):
                visited.add(url)
                continue

            final_url = _safe_url(page.url)
            if not _origin_matches(final_url, plan):
                continue
            visited.add(url)
            visited.add(final_url)

            structural_tokens = await page.evaluate(
                """() => {
                    const tokens = [];
                    const root = document.documentElement;
                    if (!root) return "";
                    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
                    let node = walker.currentNode;
                    while (node && tokens.length < 10000) {
                        const attrs = Array.from(node.attributes)
                            .map((attribute) => attribute.name.toLowerCase())
                            .sort();
                        tokens.push(node.tagName.toLowerCase() + ":" + attrs.join(","));
                        node = walker.nextNode();
                    }
                    return tokens.join("|");
                }"""
            )
            dom_sha256 = hashlib.sha256(str(structural_tokens).encode()).hexdigest()

            extracted = await page.evaluate(
                """(maximumLinks) => ({
                    links: Array.from(document.querySelectorAll("a[href], area[href]"))
                        .slice(0, maximumLinks)
                        .map((element) => element.href),
                    scripts: Array.from(document.scripts)
                        .filter((element) => element.src)
                        .slice(0, maximumLinks)
                        .map((element) => element.src),
                    forms: Array.from(document.forms).slice(0, 100).map((form) => ({
                        method: (form.method || "get").toUpperCase(),
                        action: form.action || window.location.href,
                        fields: Array.from(form.elements).slice(0, 200).map((field) => ({
                            name: field.name || "",
                            type: field.type || field.tagName || "",
                            required: Boolean(field.required)
                        }))
                    }))
                })""",
                maximum_links,
            )

            links: list[str] = []
            for candidate in extracted.get("links", []):
                candidate_text = str(candidate)
                if not _origin_matches(candidate_text, plan):
                    continue
                safe_candidate = _safe_url(candidate_text)
                if safe_candidate not in links:
                    links.append(safe_candidate)
                if (
                    depth < maximum_depth
                    and safe_candidate not in visited
                    and safe_candidate not in queued
                    and len(queued) < maximum_pages * maximum_links
                ):
                    queue.append((safe_candidate, depth + 1))
                    queued.add(safe_candidate)

            scripts: list[str] = []
            for candidate in extracted.get("scripts", []):
                candidate_text = str(candidate)
                if _origin_matches(candidate_text, plan):
                    safe_candidate = _safe_url(candidate_text)
                    if safe_candidate not in scripts:
                        scripts.append(safe_candidate)

            forms: list[dict[str, object]] = []
            for form in extracted.get("forms", []):
                method = _safe_text(form.get("method"), 16).upper()
                if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    method = "GET"
                action_text = str(form.get("action") or final_url)
                if not _origin_matches(action_text, plan):
                    continue
                action = _safe_url(action_text)
                fields = [
                    {
                        "name": _safe_field_name(field.get("name")),
                        "input_type": _safe_input_type(field.get("type")),
                        "required": bool(field.get("required", False)),
                    }
                    for field in form.get("fields", [])
                    if isinstance(field, dict)
                ]
                forms.append(
                    {
                        "form_sha256": _form_sha256(method, action, fields),
                        "method": method,
                        "action_url": action,
                        "fields": fields,
                    }
                )

            page_requests = [
                dict(item)
                for item in active_requests
                if item["url"] and _origin_matches(str(item["url"]), plan)
            ]
            pages.append(
                {
                    "url": final_url,
                    "depth": depth,
                    "status_code": response.status if response is not None else None,
                    "dom_structure_sha256": dom_sha256,
                    "links": links,
                    "scripts": scripts,
                    "forms": forms,
                    "requests": page_requests,
                }
            )

        await context.close()
        await browser.close()

    return {
        "schema_version": 1,
        "pages": pages,
        **counters,
        "budget_exhausted": budget_exhausted,
        "content_trust": "untrusted_target_content",
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("fixed worker paths are required", file=sys.stderr)
        return 2
    plan_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    try:
        plan = _load_plan(plan_path)
        result = asyncio.run(_collect(plan))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_suffix(".part")
        temporary.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(temporary, output_path)
    except (OSError, ValueError, json.JSONDecodeError, PlaywrightError) as exc:
        print(type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
