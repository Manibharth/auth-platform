# Auth and API Platform

A production-style identity and API service in Python. Users register, verify their email, log in,
receive **15-minute RS256 access tokens** and **rotating refresh tokens with reuse detection**, and call
**role-protected** endpoints. It is built with FastAPI, PostgreSQL and Redis, and deploys to GCP Cloud Run
with Terraform.

[![ci](https://github.com/Manibharth/auth-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/Manibharth/auth-platform/actions/workflows/ci.yml)
![coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)
![python](https://img.shields.io/badge/python-3.12-blue)

**Live demo:** `https://<your-cloud-run-url>/docs` (fill in after the first deploy). The demo account is
`demo@example.com`; it is read-only in production.

**Headline number (local, see [Load testing](#load-testing)):** authenticated reads at **690 req/s, p95 16 ms**
with 100 concurrent users, on 4 gunicorn workers on an 8-core laptop.

---

## Architecture

```mermaid
flowchart LR
  C[Client app] -- "HTTPS + Bearer JWT" --> LB[Cloud load balancer<br/>TLS termination]
  O[Other services] -- "GET /.well-known/jwks.json" --> LB
  LB --> MW
  subgraph API["FastAPI service (stateless, N replicas)"]
    MW["Middleware<br/>request id · rate limit · security headers · metrics"]
    R["Routers<br/>Pydantic validation · auth dependency · RBAC check"]
    S["Services<br/>register · login · token rotation · ownership · audit"]
    REPO["Repositories<br/>SQLAlchemy 2.0 async"]
    MW --> R --> S --> REPO
  end
  MW --> REDIS[(Redis<br/>rate limits · jti denylist ·<br/>revoked-before markers)]
  S --> REDIS
  REPO --> PG[(PostgreSQL<br/>users · roles · tokens ·<br/>audit log · projects)]
  S -. key at startup .-> SM[Secret Manager<br/>JWT private key, DB creds]
```

One stateless FastAPI service sits behind HTTPS. PostgreSQL and Redis hold all state, so the API scales
horizontally. Other services verify tokens with the public JWKS, so the signing key never leaves the
secret store.

**Path of one request:** TLS ends at the load balancer. Middleware adds a request id, applies the Redis
rate limit and sets security headers. The router validates input with Pydantic, and the auth dependency
checks the JWT signature, expiry, `jti` denylist and `revoked_before` marker. The permission dependency
allows or rejects the route. The service applies business rules (ownership, lockout, rotation) and writes
audit rows. The repository runs the queries inside one transaction.

Layers are strict: **routers handle HTTP, services hold the rules, repositories hold the queries.** No
router touches the database.

```
app/
├── main.py              app factory, middleware, router mounting
├── cli.py               seed, generate-key, purge-expired
├── core/                config, security (Argon2id, RS256/JWKS), logging, rate_limit,
│                        middleware, errors (RFC 9457), metrics, openapi, telemetry
├── api/deps.py          get_db, get_claims, require_permission, rate-limit deps
├── api/v1/              auth, users, projects, admin, health
├── models/              10 SQLAlchemy models
├── schemas/             Pydantic request/response models
├── services/            auth, token, rbac, audit, user, project, oauth, email
├── repositories/        database access only
└── db/                  session, base, seed data
migrations/              Alembic (schema + frozen role seed + append-only trigger)
tests/{unit,integration,security}
load/locustfile.py       4 scenarios from the spec
infra/terraform/         shared + staging + production (GCP)
.github/workflows/       ci.yml, cd.yml, deploy.yml
```

## Key design decisions

| Decision | Why |
|---|---|
| **RS256, not HS256** | Other services verify with the public key from `/.well-known/jwks.json`; the private key stays in Secret Manager. Each key has a `kid` (RFC 7638 thumbprint). JWKS also serves previous keys, so rotation (`scripts/rotate_jwt_key.sh`) never logs anyone out. |
| **15-minute access tokens** | They are short enough that a leaked token dies quickly, and long enough that clients refresh about 4× an hour. Early revocation is a Redis `jti` denylist (logout) plus a per-user `revoked_before` timestamp (logout-all, password reset, disable). That costs one Redis `MGET` per request. |
| **Rotating refresh tokens, 14 days** | They are opaque 256-bit tokens, stored only as SHA-256 hashes. Each refresh marks the old token used and issues a new one in the same `family_id`. Presenting a used token is treated as theft: the whole family is revoked and audited. A `SELECT … FOR UPDATE` row lock means two parallel refreshes cannot both succeed. |
| **404, not 403, for other users' projects** | A 403 would confirm that the resource exists. B gets the same 404 for A's project as for a random UUID. |
| **Argon2id** | It is memory-hard, so GPU cracking is expensive, and it is OWASP's first choice. Defaults are OWASP's minimum (19 MiB, t=2). `scripts/tune_argon2.py` measures on the target instance; aim for 50–100 ms. Legacy bcrypt hashes verify and are upgraded on the next login. Hashing runs in a thread pool so it never blocks the event loop. |
| **Generic login errors + dummy hash** | Unknown email, wrong password and locked account return identical bodies. Unknown emails still run an Argon2 verify, so timing does not reveal which accounts exist. Register and forgot-password always answer 202; a duplicate signup emails the real owner instead. |
| **Admin routes re-read roles from the DB** | Roles in the token are a hint (≤15 min stale). `user:manage` and `audit:read` are checked against the database, so a demoted admin loses access on the next request. |
| **Cursor pagination on `(created_at, id)`** | Pages stay stable under concurrent inserts (tested). Cursors are opaque, and a malformed cursor returns 400, never 500. |
| **Idempotency-Key in PostgreSQL** | The key row is claimed with `INSERT … ON CONFLICT DO NOTHING` in the same transaction as the project row. Concurrent duplicates block on the PK index and then replay the stored response. A different body with the same key returns 422. Keys expire after 24 h. |
| **Append-only audit log** | A database trigger rejects `UPDATE`/`DELETE` whatever role the app uses, and the repository has no update or delete method. |
| **Redis-down policy** | Login fails closed (503) because brute-force protection must not silently disappear. Denylist checks and the global limiter fail open (logged), degrading to the 15-minute token lifetime. |
| **Migrations are a release step** | `alembic upgrade head` runs in a Cloud Run job (and a compose `migrate` service), never at app start. |

## Security model

OWASP Top 10 (2021 names; check the current edition before you quote it). Each control maps to a test.
The full STRIDE table is in [docs/threat-model.md](docs/threat-model.md).

| OWASP risk | Control | Test that proves it |
|---|---|---|
| A01 Broken access control | `require_permission` on every route, ownership in the service, 404 for foreign resources | [`test_access_control.py`](tests/security/test_access_control.py): a parametrised matrix of all 17 protected operations (anonymous → 401, denied role → 403/404, allowed role → 2xx), plus "user B reads, edits and deletes A's project and always gets 404" |
| A02 Cryptographic failures | Argon2id, RS256 only, hashed stored tokens, Fernet-encrypted TOTP secrets, TLS at the LB, HSTS | [`test_token_forgery.py`](tests/security/test_token_forgery.py): wrong key with the same kid, `alg: none`, HS256 signed with the public key, wrong kid, wrong aud/iss/typ, expired → all 401 |
| A03 Injection | SQLAlchemy bound parameters, Pydantic validation (`extra="forbid"`), LIKE-escaping | SQL-injection payloads in every string field ([`test_hardening.py`](tests/security/test_hardening.py)) plus Schemathesis fuzzing in CI |
| A04 Insecure design | Threat model, rate limits, lockout, reuse detection | Brute force → 429 then a lock; a reused refresh token revokes the family |
| A05 Security misconfiguration | Security headers on every response, CORS allow-list (wildcard rejected at startup), docs CSP, non-root container | Header test on 6 paths including error responses; Trivy in CI |
| A06 Vulnerable components | `uv.lock`, Dependabot (uv, actions, docker, terraform), pip-audit, Trivy | CI fails on a known vulnerability or a fixable HIGH/CRITICAL |
| A07 Identification & auth failures | 15-min tokens, rotation, lockout, generic errors, optional TOTP MFA | Expired token → 401; unknown-email and wrong-password responses are byte-identical |
| A08 Software & data integrity | Actions pinned to SHAs, image built once in CI, OIDC deploy (no cloud keys in GitHub) | [Workflow review checklist](docs/workflow-review-checklist.md) |
| A09 Logging & monitoring failures | Audit log for logins, failures, locks, role changes, revocations; JSON logs with request id; redaction | A role change creates exactly one audit row with actor, target, old and new |
| A10 SSRF | No fetch of user-supplied URLs (only fixed Google OAuth endpoints) | Not applicable until webhooks are added (noted in the threat model) |

## Quick start

```bash
cp .env.example .env
docker compose up --build        # postgres, redis, migrate (key + alembic + seed), app
open http://localhost:8000/docs
```

The `migrate` service generates a local JWT key into a volume, runs `alembic upgrade head` and seeds
roles, a demo admin and a demo user from `.env`. To run without Docker:

```bash
uv sync --dev
export DATABASE_URL=postgresql+asyncpg://auth:auth@localhost:5432/auth REDIS_URL=redis://localhost:6379/0
uv run python -m app.cli generate-key --out secrets/jwt_private.pem && export JWT_PRIVATE_KEY_FILE=secrets/jwt_private.pem
uv run alembic upgrade head && uv run python -m app.cli seed
uv run uvicorn --factory app.main:create_app --reload
```

Sample session with curl:

```bash
TOKEN=$(curl -s localhost:8000/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"demo@example.com","password":"change-me-demo-passphrase"}' | jq -r .access_token)
curl -s localhost:8000/v1/users/me -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/v1/projects -H "Authorization: Bearer $TOKEN" -H 'Idempotency-Key: demo-1' \
  -H 'content-type: application/json' -d '{"name":"My project"}'
```

### Endpoints (31)

| Area | Endpoints |
|---|---|
| Auth | `POST /v1/auth/register` · `verify-email` · `login` · `login/mfa` · `refresh` · `logout` · `logout-all` · `password/forgot` · `password/reset` · `password/change` · `mfa/enroll` · `mfa/verify` · `mfa/disable` · `GET oauth/google/authorize` · `GET oauth/google/callback` · `GET /.well-known/jwks.json` |
| Users | `GET` · `PATCH` · `DELETE /v1/users/me` |
| Projects | `POST` · `GET /v1/projects` · `GET` · `PATCH` · `DELETE /v1/projects/{id}` |
| Admin | `GET /v1/admin/users` · `GET /v1/admin/users/{id}` · `PATCH …/{id}/roles` · `POST …/{id}/disable` · `GET /v1/admin/audit-log` |
| Ops | `GET /healthz` · `GET /readyz` · `GET /metrics` (allow-listed CIDRs + optional bearer token) |

All errors are RFC 9457 `application/problem+json` with a stable `code` and the `request_id`. The OpenAPI
document is committed at [`openapi/openapi.json`](openapi/openapi.json). CI fails if the API changes
without updating it.

## Tests

```bash
# against running services (CI uses service containers)
TEST_DATABASE_URL=postgresql+asyncpg://auth:auth@localhost:5432/auth_test \
TEST_REDIS_URL=redis://localhost:6379/1 uv run pytest --cov=app --cov-fail-under=80
# or leave both unset: Testcontainers starts PostgreSQL 16 and Redis 7 in Docker
uv run pytest
```

**170 tests, 91% line+branch coverage, ~15 s.** Everything runs against real PostgreSQL and Redis, never
SQLite.

| Layer | What it covers |
|---|---|
| Unit (28) | Argon2/bcrypt, password policy (Hypothesis), JWT sign/verify/rotation, cursors (Hypothesis), log redaction, config fail-fast |
| Integration (47) | Every auth flow, MFA, Google PKCE (mocked IdP), projects + idempotency races, admin + audit, ops, rate limiter, **every migration up/down on an empty DB**, model/migration drift |
| Security (95) | Token forgery, refresh reuse + **parallel refresh (exactly one wins)**, brute force + lockout, full access matrix, headers, CORS, SQL-injection payloads, append-only audit |
| Contract/fuzz | Schemathesis in CI, anonymous and as admin: no 5xx, status codes, content types and bodies match the schema (6,470 cases, 0 failures locally) |

All 12 test cases from the spec are covered:

1. Duplicate email is answered like a new signup, and the owner gets a warning email.
2. Expired, wrong-signature, tampered-role, `alg: none` and wrong-kid tokens all return 401.
3. A reused refresh token revokes the family, and the newest token stops working.
4. Parallel refresh with the same token: exactly one succeeds.
5. A logged-out token is rejected through the `jti` denylist.
6. A normal user gets 403 on admin routes; anonymous gets 401.
7. User B gets 404 on reads, updates and deletes of user A's project.
8. Six wrong passwords lock the account, and the right password is refused during the lock.
9. A reset token works once, expires on time and revokes every session.
10. An Idempotency-Key replay returns the first response and creates one row (including under a concurrent race).
11. A role change writes exactly one audit row with old and new roles.
12. Every Alembic migration upgrades and downgrades cleanly.

## Load testing

Scenarios are in [`load/locustfile.py`](load/locustfile.py). Seed accounts with `load/seed_load_users.py`,
then run one user class at a time.

> **Caveat:** the numbers below are from a **local** run on an 8-core Apple-silicon laptop. Locust,
> gunicorn (4 uvicorn workers), PostgreSQL 16 and Redis 7 all shared the machine. The spec calls for
> staging on the production instance size; rerun there and replace this table before quoting it.
> Date: 2026-11-18. Argon2id t=2, m=19 MiB. Rate limits disabled for the run.

**Target:** p95 < 50 ms for authenticated reads at 100 concurrent users. **Met (16 ms).**

| Scenario | Users | Throughput | p50 | p95 | p99 | Errors |
|---|---:|---:|---:|---:|---:|---:|
| Authenticated read `GET /v1/projects` | 100 | 690 req/s | 3 ms | 16 ms | 120 ms | 0 / 41,461 |
| Token refresh (rotation + row lock) | 50 | 362 req/s | 8 ms | 24 ms | 61 ms | 0 / 21,359 |
| Login (Argon2id, CPU-bound by design) | 50 | 150 req/s | 180 ms | 420 ms | 610 ms | 0 / 8,919 |
| Mixed 80/15/5, 10 min (all requests) | 100 | 574 req/s | 27 ms | 150 ms | 300 ms | 57 / 344,200 |
| ↳ reads | | 460 req/s | 24 ms | 120 ms | 250 ms | |
| ↳ writes (with Idempotency-Key) | | 85 req/s | 36 ms | 170 ms | 320 ms | |
| ↳ logins | | 29 req/s | 94 ms | 310 ms | 520 ms | |

**One change, before and after:** caching the role → permission map in-process (60 s TTL) instead of
querying it on every request:

| Authenticated read, 100 users | p95 | p99 |
|---|---:|---:|
| Before (`PERMISSION_CACHE_TTL_SECONDS=0`) | 35 ms | 110 ms |
| After (60 s cache) | **16 ms** | 120 ms |

Throughput is client-paced in both runs, so the p95 drop is the signal. In the mixed run, Argon2 logins
compete with reads for the same 8 cores, which is why read p95 rises from 16 ms to 120 ms. That is a good
argument for a dedicated login pool or a separate instance class in production. All 57 mixed-run errors
were TCP resets (0.017%), with no HTTP 5xx. They coincide with gunicorn recycling workers every ~10k
requests (`max_requests`). At 300 users the laptop
saturated (p95 ≈ 310 ms). The connection resets seen during ramp-up came from macOS's
`somaxconn=128` listen backlog, not the app.

## Deployment

GCP: Cloud Run + Cloud SQL (private IP) + Memorystore + Secret Manager, provisioned by Terraform in
[`infra/terraform`](infra/terraform). See [docs/infrastructure.md](docs/infrastructure.md) for the diagram,
bootstrap order and the AWS mapping.

- **ci.yml** (every push/PR): ruff, mypy `--strict`, bandit, pip-audit, OpenAPI snapshot diff, Alembic
  up/down, pytest with an 80% gate on real Postgres/Redis, Schemathesis, Docker build and Trivy. Every
  action is pinned to a commit SHA.
- **cd.yml** (after CI passes on main): build the image once and push it tagged with the SHA (OIDC, no
  stored keys). Then **staging**: migrate job, deploy with no traffic, smoke test the candidate, shift
  traffic, smoke test again, roll back automatically on failure. Then **production**: same steps behind
  manual approval through the `production` environment.
- The image is a multi-stage uv build on a slim, non-root base (uid 10001) with a `HEALTHCHECK` on
  `/healthz`, run by gunicorn with uvicorn workers (one per CPU).
- Alerts: 5xx ratio > 2% over 5 min, and Cloud Run p95 latency > 300 ms.

## Observability

- **Logs:** structlog JSON with `request_id` on every line (honours an incoming `X-Request-ID`). Tokens,
  passwords, cookies and JWTs are redacted, and emails are masked (`a***@example.com`).
- **Metrics** (`/metrics`, multi-process safe): `http_requests_total{method,route,status}`,
  `http_request_duration_seconds`, `auth_login_failures_total{reason}`, `auth_login_success_total`,
  `auth_refresh_reuse_total`, `rate_limit_hits_total{scope}`, `db_pool_connections_in_use`.
- **Traces:** OpenTelemetry for FastAPI, SQLAlchemy and Redis (`OTEL_ENABLED=true`,
  `OTEL_EXPORTER_OTLP_ENDPOINT`).
- **Health:** `/healthz` for liveness and `/readyz` for readiness (DB and Redis with 2 s timeouts, 503 if
  either is down).

## Configuration

All settings are environment variables (Pydantic Settings). See
[`app/core/config.py`](app/core/config.py) and [`.env.example`](.env.example). Staging and production
**refuse to start** without a JWT key, with the console email backend, or with a CORS wildcard.

## Known limits and what I would do next

- **No live URL yet.** Terraform and the CD pipeline are written and validated, but nothing has been
  applied to a cloud account. The load numbers above are local.
- The Docker image and Trivy scan have not been run locally (no Docker on the build machine); CI runs both.
- Email goes through SMTP (any relay). There are no templates or bounce handling.
- Next: device/session management UI (list and revoke individual refresh families), WebAuthn/passkeys,
  a breached-password check (HIBP k-anonymity), tenant isolation, partitioning `audit_log` by month,
  and a comparison against a managed IdP (Cognito / Identity Platform / Auth0).

## Interview crib sheet

| Question | Short answer |
|---|---|
| Why RS256 and not HS256? | Other services verify with the public key only; the signing secret never leaves Secret Manager. |
| What if a refresh token is stolen? | Rotation plus reuse detection revokes the family on the next use by either party; the access token dies within 15 minutes. |
| How do you revoke an access token early? | Redis `jti` denylist until expiry, plus a per-user `revoked_before` timestamp; one `MGET` per request. |
| Why 404 instead of 403? | It does not confirm that the resource exists. |
| Why Argon2id? | It is memory-hard, so GPU cracking is expensive. Tune it to the instance (50–100 ms). |
| How does it scale to millions of users? | The API is stateless, so add instances. Then add read replicas, cache permission lookups, partition the audit log, and verify tokens at the edge with the JWKS. |
| What if Redis is down? | Login fails closed (503); denylist and global limits degrade to the 15-minute token lifetime. |
