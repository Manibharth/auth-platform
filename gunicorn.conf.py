"""Gunicorn with uvicorn workers; worker count follows the CPU count."""

import multiprocessing
import os
import shutil

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
worker_class = "uvicorn.workers.UvicornWorker"
workers = int(os.environ.get("WEB_CONCURRENCY", multiprocessing.cpu_count()))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "30"))
graceful_timeout = 20
keepalive = 5
max_requests = 10000
max_requests_jitter = 1000
accesslog = None  # the app logs every request as structured JSON
errorlog = "-"
# Trust X-Forwarded-For only from the load balancer (Cloud Run sets this).
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")


def on_starting(server):
    path = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if path:
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path, exist_ok=True)


def child_exit(server, worker):
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        from prometheus_client import multiprocess

        multiprocess.mark_process_dead(worker.pid)
