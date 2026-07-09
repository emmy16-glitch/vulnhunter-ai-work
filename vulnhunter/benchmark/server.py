"""Loopback-only HTTP server for deterministic benchmark scenarios."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType

from vulnhunter.benchmark.catalog import SCENARIOS
from vulnhunter.benchmark.models import BenchmarkPage


class _BenchmarkHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class BenchmarkServer(AbstractContextManager["BenchmarkServer"]):
    """Serve the fixed benchmark catalog on an ephemeral loopback port."""

    def __init__(self) -> None:
        self._routes: dict[str, BenchmarkPage] = {
            page.path: page for scenario in SCENARIOS for page in scenario.pages
        }
        self._server: _BenchmarkHttpServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> BenchmarkServer:
        routes = self._routes

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_HEAD(self) -> None:  # noqa: N802
                self._respond(include_body=False)

            def do_GET(self) -> None:  # noqa: N802
                self._respond(include_body=True)

            def _respond(self, *, include_body: bool) -> None:
                path = self.path.split("?", 1)[0]
                page = routes.get(path)

                if page is None:
                    body = b"Not found"
                    self.send_response_only(404)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if include_body:
                        self.wfile.write(body)
                    return

                body = page.body.encode("utf-8")
                self.send_response_only(page.status_code)
                self.send_header("Content-Type", page.content_type)
                for name, value in page.headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if include_body:
                    self.wfile.write(body)

        self._server = _BenchmarkHttpServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="vulnhunter-benchmark-server",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Benchmark server is not running.")
        return int(self._server.server_address[1])

    def scenario_url(self, scenario_id: str) -> str:
        """Return the loopback target URL for one isolated scenario."""
        return f"http://127.0.0.1:{self.port}/benchmark/{scenario_id}/"

    def urls(self) -> Iterator[str]:
        """Yield all catalog target URLs in deterministic order."""
        for scenario in SCENARIOS:
            yield self.scenario_url(scenario.scenario_id)
