"""Conservative Gunicorn configuration for reviewed production activation."""

from __future__ import annotations

import os


def bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


bind = os.environ.get("VULNHUNTER_GUNICORN_BIND", "127.0.0.1:8002")
workers = bounded_int("VULNHUNTER_GUNICORN_WORKERS", 1, 1, 2)
worker_class = "sync"
threads = bounded_int("VULNHUNTER_GUNICORN_THREADS", 1, 1, 2)
timeout = bounded_int("VULNHUNTER_GUNICORN_TIMEOUT", 60, 15, 300)
graceful_timeout = bounded_int("VULNHUNTER_GUNICORN_GRACEFUL_TIMEOUT", 30, 5, 120)
keepalive = bounded_int("VULNHUNTER_GUNICORN_KEEPALIVE", 2, 1, 10)
max_requests = bounded_int("VULNHUNTER_GUNICORN_MAX_REQUESTS", 1000, 100, 10000)
max_requests_jitter = bounded_int("VULNHUNTER_GUNICORN_MAX_REQUESTS_JITTER", 50, 0, 1000)
preload_app = False
accesslog = "-"
errorlog = "-"
capture_output = False
forwarded_allow_ips = os.environ.get("VULNHUNTER_GUNICORN_FORWARDED_ALLOW_IPS", "127.0.0.1")
secure_scheme_headers = {"X-FORWARDED-PROTO": "https"}
