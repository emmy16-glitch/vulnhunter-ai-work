#!/usr/bin/env python3
"""Run a deliberately limited HTTP target on one RFC1918 Codespaces address."""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ALLOWED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def validate_lab_address(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("the phone lab currently requires an IPv4 RFC1918 address")
    if address.is_loopback or address.is_link_local or not any(
        address in network for network in _ALLOWED_NETWORKS
    ):
        raise ValueError("the phone lab target must use a non-loopback RFC1918 address")
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
    raise RuntimeError("no non-loopback RFC1918 Codespaces address was found")


class PhoneLabHandler(BaseHTTPRequestHandler):
    server_version = "VulnHunterPhoneLab/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            body = b'{"status":"ready"}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/":
            self.send_error(404)
            return
        body = (
            b"<!doctype html><html><head><title>VulnHunter Phone Lab</title></head>"
            b"<body><h1>Authorized private laboratory target</h1>"
            b"<p>This service deliberately omits X-Content-Type-Options so the reviewed "
            b"passive template has genuine evidence to record.</p></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # Deliberately no X-Content-Type-Options header: this is the reviewed lab signal.
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"phone-lab-target {self.address_string()} {format % args}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--print-address", action="store_true")
    arguments = parser.parse_args()
    host = validate_lab_address(arguments.host) if arguments.host else discover_lab_address()
    if arguments.print_address:
        print(host)
        return 0
    if not 1 <= arguments.port <= 65_535:
        parser.error("--port must be between 1 and 65535")
    server = ThreadingHTTPServer((host, arguments.port), PhoneLabHandler)
    print(f"VulnHunter phone lab target listening on http://{host}:{arguments.port}/", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
