"""Prometheus metrics. Works in single-process and gunicorn multi-process mode
(set PROMETHEUS_MULTIPROC_DIR)."""

from __future__ import annotations

import os

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)
from prometheus_client import REGISTRY as DEFAULT_REGISTRY

HTTP_REQUESTS = Counter("http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0),
)
LOGIN_FAILURES = Counter("auth_login_failures_total", "Failed logins", ["reason"])
LOGIN_SUCCESS = Counter("auth_login_success_total", "Successful logins")
REFRESH_REUSE = Counter("auth_refresh_reuse_total", "Refresh-token reuse events (family revoked)")
RATE_LIMIT_HITS = Counter("rate_limit_hits_total", "Requests rejected by a rate limit", ["scope"])
DB_POOL_CHECKED_OUT = Gauge(
    "db_pool_connections_in_use", "Checked-out DB connections", multiprocess_mode="livesum"
)
DB_POOL_SIZE = Gauge("db_pool_size", "Configured DB pool size", multiprocess_mode="max")


def render_latest() -> tuple[bytes, str]:
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
        return generate_latest(registry), CONTENT_TYPE_LATEST
    return generate_latest(DEFAULT_REGISTRY), CONTENT_TYPE_LATEST
