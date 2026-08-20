"""Local deterministic application used only by Browser Intelligence acceptance."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


class _FixtureHandler(BaseHTTPRequestHandler):
    server_version = "VulnHunterBrowserFixture/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/login":
            self._send_html(
                """
                <!doctype html>
                <html><head><title>Fixture Login</title></head><body>
                <main><h1>Local Browser Intelligence</h1>
                <form id="login-form" method="post" action="/dashboard">
                  <label>Username <input id="username" name="username" type="text"></label>
                  <label>Password <input id="password" name="password" type="password"></label>
                </form>
                <a id="login-button" href="/dashboard">Sign in</a>
                <p id="status">Awaiting sign in</p>
                <script>
                  console.log('browser-intelligence-fixture-login');
                  fetch('/api/profile');
                  fetch('/api/settings');
                </script></main></body></html>
                """
            )
            return
        if self.path == "/dashboard":
            self._send_html(
                """
                <!doctype html>
                <html><head><title>Fixture Dashboard</title></head><body>
                <main><h1>Dashboard ready</h1><p id="state">Profile and settings loaded.</p>
                <p id="js-state">JavaScript pending</p>
                <img src="/api/profile" alt="profile">
                <img src="/api/settings" alt="settings">
                <a href="/dashboard/details">Details</a>
                <script>document.querySelector('#js-state').textContent='JavaScript executed';
                console.error('browser-intelligence-fixture-console');
                fetch('/api/profile'); fetch('/api/settings');</script></main></body></html>
                """
            )
            return
        if self.path == "/dashboard/details":
            self._send_html(
                "<html><head><title>Fixture Details</title></head>"
                "<body><h1>Details</h1></body></html>"
            )
            return
        if self.path == "/api/profile":
            self._send_json({"display_name": "fixture-user", "role": "tester"})
            return
        if self.path == "/api/settings":
            self._send_json({"theme": "warm", "feature": "browser-intelligence"})
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/dashboard":
            self._send_html(
                "<html><head><title>Fixture Dashboard</title></head>"
                "<body><main><h1>Dashboard ready</h1>"
                '<p id="state">Profile and settings loaded.</p>'
                '<p id="js-state">JavaScript pending</p>'
                '<img src="/api/profile" alt="profile"><img src="/api/settings" alt="settings">'
                "<script>document.querySelector('#js-state').textContent='JavaScript executed';"
                "console.error('browser-intelligence-fixture-console');"
                "fetch('/api/profile'); fetch('/api/settings');</script>"
                "</main></body></html>"
            )
            return
        self.send_error(405)

    def _send_html(self, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: dict[str, object]) -> None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def local_browser_fixture() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
