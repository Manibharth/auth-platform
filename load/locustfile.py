"""Locust scenarios from the spec.

    # one scenario at a time (pick the user class):
    locust -f load/locustfile.py --host https://staging-url AuthenticatedReadUser
    locust -f load/locustfile.py --host ... TokenRefreshUser
    locust -f load/locustfile.py --host ... LoginUser
    locust -f load/locustfile.py --host ... MixedTrafficUser --run-time 10m

Accounts: set LOAD_USER_PREFIX / LOAD_PASSWORD / LOAD_USER_COUNT and create them with
`python load/seed_load_users.py` first (they must be verified). Disable or raise the
login rate limits on the target environment for the login scenario only.
"""

from __future__ import annotations

import os
import random
import uuid

from locust import HttpUser, between, events, task

PREFIX = os.environ.get("LOAD_USER_PREFIX", "load")
PASSWORD = os.environ.get("LOAD_PASSWORD", "load-test-passphrase-42")
COUNT = int(os.environ.get("LOAD_USER_COUNT", "50"))


def account() -> str:
    return f"{PREFIX}-{random.randrange(COUNT)}@loadtest.example"


class _Authenticated(HttpUser):
    abstract = True
    wait_time = between(0.05, 0.2)

    def on_start(self) -> None:
        self.email = account()
        self._login()

    def _login(self) -> None:
        with self.client.post(
            "/v1/auth/login",
            json={"email": self.email, "password": PASSWORD},
            name="POST /v1/auth/login",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"login {resp.status_code}")
                return
            body = resp.json()
            self.access, self.refresh = body["access_token"], body["refresh_token"]

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access}"}


class AuthenticatedReadUser(_Authenticated):
    """Steady-state API speed: the number for the resume."""

    @task
    def list_projects(self) -> None:
        self.client.get("/v1/projects?limit=20", headers=self.auth, name="GET /v1/projects")


class TokenRefreshUser(_Authenticated):
    """Cost of rotation and the row lock."""

    @task
    def refresh(self) -> None:
        with self.client.post(
            "/v1/auth/refresh",
            json={"refresh_token": self.refresh},
            name="POST /v1/auth/refresh",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                body = resp.json()
                self.access, self.refresh = body["access_token"], body["refresh_token"]
            else:
                resp.failure(f"refresh {resp.status_code}")
                self._login()


class LoginUser(HttpUser):
    """CPU cost of Argon2id; throughput is CPU-bound by design."""

    wait_time = between(0.05, 0.2)

    @task
    def login(self) -> None:
        self.client.post(
            "/v1/auth/login",
            json={"email": account(), "password": PASSWORD},
            name="POST /v1/auth/login",
        )


class MixedTrafficUser(_Authenticated):
    """80% reads, 15% writes, 5% logins. Run for at least 10 minutes."""

    @task(80)
    def read(self) -> None:
        self.client.get("/v1/projects?limit=20", headers=self.auth, name="GET /v1/projects")

    @task(15)
    def write(self) -> None:
        self.client.post(
            "/v1/projects",
            json={"name": f"load {uuid.uuid4().hex[:8]}"},
            headers={**self.auth, "Idempotency-Key": uuid.uuid4().hex},
            name="POST /v1/projects",
        )

    @task(5)
    def login(self) -> None:
        self._login()


@events.init_command_line_parser.add_listener
def _(parser) -> None:  # type: ignore[no-untyped-def]
    parser.add_argument("--note", default="", help="free text recorded with the run")
