#!/usr/bin/env python3
"""Run a deliberate private web target for passive browser-perception acceptance."""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_ALLOWED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_COUNTERS = {
    "api_info_hits": 0,
    "profile_hits": 0,
    "mutate_hits": 0,
    "submit_hits": 0,
    "websocket_hits": 0,
    "outside_hits": 0,
}
_COUNTER_LOCK = threading.Lock()


def validate_lab_address(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("web perception lab requires an IPv4 RFC1918 address")
    if (
        address.is_loopback
        or address.is_link_local
        or not any(address in network for network in _ALLOWED_NETWORKS)
    ):
        raise ValueError("web perception lab target must use a non-loopback RFC1918 address")
    return str(address)


def discover_lab_address() -> str:
    completed = subprocess.run(
        ("ip", "-j", "-4", "address", "show", "scope", "global"),
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    for interface in json.loads(completed.stdout):
        for item in interface.get("addr_info", []):
            local = item.get("local")
            if not isinstance(local, str):
                continue
            try:
                return validate_lab_address(local)
            except ValueError:
                continue
    raise RuntimeError("no non-loopback RFC1918 address was found")


def _increment(name: str) -> None:
    with _COUNTER_LOCK:
        _COUNTERS[name] += 1


class PerceptionLabHandler(BaseHTTPRequestHandler):
    server_version = "VulnHunterWebPerceptionLab/1.0"

    def _write(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._write(200, b'{"status":"ready"}\n', content_type="application/json")
            return
        if path == "/counters":
            with _COUNTER_LOCK:
                payload = json.dumps(_COUNTERS, sort_keys=True).encode() + b"\n"
            self._write(200, payload, content_type="application/json")
            return
        if path == "/app/":
            body = b"""<!doctype html>
<html>
<head><title>Perception Lab alice@example.com</title></head>
<body>
  <a href="/app/profile?token=browser-query-secret">Profile</a>
  <a href="/application/outside">Outside boundary</a>
  <form method="post" action="/app/submit">
    <input name="username" value="alice">
    <input name="password" type="password" value="browser-form-secret" required>
    <button type="submit">Never submit this form</button>
  </form>
  <script src="/app/static/app.js"></script>
</body>
</html>"""
            self._write(200, body, content_type="text/html; charset=utf-8")
            return
        if path == "/app/profile":
            _increment("profile_hits")
            body = b"""<!doctype html><html><head><title>Profile</title></head>
<body><a href="/app/">Home</a></body></html>"""
            self._write(200, body, content_type="text/html; charset=utf-8")
            return
        if path == "/app/static/app.js":
            body = b"""
fetch('/app/api/info?token=browser-query-secret');
fetch('/app/api/mutate', {
  method: 'POST',
  headers: {'Content-Type': 'text/plain'},
  body: 'browser-post-secret'
});
fetch('/application/outside');
new WebSocket(`ws://${location.host}/app/ws?token=browser-ws-secret`);
"""
            self._write(200, body, content_type="application/javascript")
            return
        if path == "/app/api/info":
            _increment("api_info_hits")
            self._write(
                200,
                b'{"api_key":"browser-api-secret","status":"ok"}\n',
                content_type="application/json",
            )
            return
        if path == "/app/ws":
            _increment("websocket_hits")
            self._write(400, b"websocket must have been blocked\n", content_type="text/plain")
            return
        if path.startswith("/application"):
            _increment("outside_hits")
            self._write(200, b"out of scope\n", content_type="text/plain")
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(min(length, 100_000))
        if path == "/app/api/mutate":
            _increment("mutate_hits")
            self._write(200, b"mutation should be blocked\n", content_type="text/plain")
            return
        if path == "/app/submit":
            _increment("submit_hits")
            self._write(200, b"form should never be submitted\n", content_type="text/plain")
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        print(f"web-perception-lab {self.address_string()} {format % args}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=8012)
    parser.add_argument("--print-address", action="store_true")
    arguments = parser.parse_args()
    host = validate_lab_address(arguments.host) if arguments.host else discover_lab_address()
    if arguments.print_address:
        print(host)
        return 0
    if not 1 <= arguments.port <= 65_535:
        parser.error("--port must be between 1 and 65535")

    server = ThreadingHTTPServer((host, arguments.port), PerceptionLabHandler)
    print(
        f"VulnHunter web perception lab listening on http://{host}:{arguments.port}/app/",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
