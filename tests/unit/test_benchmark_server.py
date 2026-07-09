"""Tests for the loopback-only deterministic benchmark server."""

import httpx

from vulnhunter.benchmark import BenchmarkServer


def test_benchmark_server_serves_only_catalog_routes() -> None:
    with BenchmarkServer() as server:
        root = httpx.get(
            server.scenario_url("sensitive-admin-alpha"),
            timeout=5,
        )
        missing = httpx.get(
            f"http://127.0.0.1:{server.port}/outside-benchmark/",
            timeout=5,
        )

    assert root.status_code == 200
    assert "Sensitive admin alpha" in root.text
    assert "server" not in root.headers
    assert missing.status_code == 404


def test_benchmark_server_exposes_controlled_debug_page() -> None:
    with BenchmarkServer() as server:
        response = httpx.get(
            f"http://127.0.0.1:{server.port}/benchmark/sensitive-admin-alpha/error.html",
            timeout=5,
        )

    assert response.status_code == 500
    assert "Traceback (most recent call last)" in response.text
    assert response.headers["server"] == "AlphaStack/1.4"
