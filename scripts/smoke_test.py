"""Post-deploy smoke test: /readyz, a login, and one authorised call.

SMOKE_EMAIL=... SMOKE_PASSWORD=... python scripts/smoke_test.py https://service-url
"""

from __future__ import annotations

import os
import sys
import time

import httpx


def main(base_url: str) -> int:
    email, password = os.environ["SMOKE_EMAIL"], os.environ["SMOKE_PASSWORD"]
    with httpx.Client(base_url=base_url.rstrip("/"), timeout=10) as client:
        for attempt in range(10):  # new revisions can take a few seconds to warm up
            ready = client.get("/readyz")
            if ready.status_code == 200:
                break
            time.sleep(3 * (attempt + 1))
        else:
            print(f"readyz failed: {ready.status_code} {ready.text}")
            return 1
        login = client.post("/v1/auth/login", json={"email": email, "password": password})
        if login.status_code != 200:
            print(f"login failed: {login.status_code} {login.text}")
            return 1
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        for path in ("/v1/users/me", "/v1/projects"):
            resp = client.get(path, headers=headers)
            if resp.status_code != 200:
                print(f"{path} failed: {resp.status_code} {resp.text}")
                return 1
        jwks = client.get("/.well-known/jwks.json")
        if jwks.status_code != 200 or not jwks.json().get("keys"):
            print("jwks failed")
            return 1
    print("smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
