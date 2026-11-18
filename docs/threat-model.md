# Threat model

STRIDE pass over the components in the README architecture diagram. Each row names the
control and the test (or CI gate) that proves it.

| # | Threat | Asset / entry point | Control | Proof |
|---|--------|---------------------|---------|-------|
| S1 | Credential stuffing / password spraying | `POST /v1/auth/login` | Per-IP and per-account sliding-window limits (Redis), per-IP failure ceiling, Argon2id cost | `tests/security/test_brute_force.py` |
| S2 | Online brute force of one account | `users.failed_logins`, `locked_until` | Lock after 5 failures with doubling delay (1 min → 1 h cap); generic error during lock | `test_lockout_after_failures_refuses_correct_password` |
| S3 | Account enumeration | register, login, forgot-password | Identical responses + dummy Argon2 verify for unknown emails; register/forgot always 202 | `test_unknown_email_and_wrong_password_look_identical`, `test_duplicate_email_answered_like_new_signup` |
| S4 | Forged access token | every protected route | RS256 only, `alg` pinned, `kid` must be known, `iss`/`aud`/`typ` checked | `tests/security/test_token_forgery.py` |
| S5 | Stolen refresh token | `POST /v1/auth/refresh` | Rotation + reuse detection revokes the whole family; hashed at rest | `tests/security/test_refresh_reuse.py` |
| T1 | Tampered role claim | JWT payload | Signature covers claims; admin routes re-read roles from DB | `test_tampered_role_claim`, `test_demoted_admin_loses_admin_access_immediately` |
| T2 | Audit log tampering | `audit_log` | DB trigger rejects UPDATE/DELETE; repository has no update/delete method | `test_audit_log_is_append_only_in_the_database` |
| R1 | User denies an admin action | role changes, disables, revocations | Audit row with actor, target, IP, old/new values | `test_role_change_writes_exactly_one_audit_row` |
| I1 | DB leak exposes sessions | `refresh_tokens`, `one_time_tokens` | Only SHA-256 hashes stored; Argon2id for passwords; TOTP secrets Fernet-encrypted | `test_register_verify_login` (no raw token in DB) |
| I2 | Cross-user data access (IDOR) | `/v1/projects/{id}` | Ownership check in the service; 404 not 403 | `test_user_b_gets_404_on_user_a_project` |
| I3 | Secrets in logs | structlog output | Redaction processor masks tokens, passwords, emails | `test_logs_redact_secrets_and_mask_emails` |
| I4 | Signing key exposure | JWT private key | Secret Manager only, never in image, repo or Terraform state; JWKS publishes public parts | `test_jwks_has_public_parts_only`, `.dockerignore`, `detect-secrets` |
| D1 | Request floods | all routes | Global per-IP limit (fails open), login limits (fail closed), Cloud Run max instances | `test_global_rate_limit`, `test_login_fails_closed_when_redis_down` |
| D2 | Attacker locks a victim out | lockout | Lock is temporary and capped at 1 h; failed attempts during a lock do not extend it; reset link unlocks | `test_lock_expires_and_counter_resets`, `test_reset_unlocks_account` |
| D3 | Argon2 CPU exhaustion | login | Per-IP login limit; hashing runs in a thread pool so the event loop stays responsive | load test "Login" scenario |
| E1 | Normal user reaches admin routes | `/v1/admin/*` | `require_permission` dependency, DB-backed for sensitive permissions | `test_denied_role_rejected[...]` |
| E2 | Replayed TOTP code | `POST /v1/auth/login/mfa` | Each code accepted once (Redis NX key for 90 s) | `test_mfa_enroll_and_two_step_login` |
| E3 | Login CSRF via refresh cookie | `/v1/auth/refresh` | Cookie is `HttpOnly; Secure; SameSite=Strict`, path-scoped to `/v1/auth` | `test_refresh_via_cookie` |

## Out of scope / accepted risks

* **SSRF** — the service never fetches user-supplied URLs. The only outbound calls are to fixed Google
  OAuth endpoints. Revisit when webhooks are added.
* **Access tokens survive up to 15 minutes after a role downgrade** on non-admin routes (roles in the
  token are a hint). Admin routes re-read from the database. Logout, logout-all, password reset and
  account disable revoke immediately through the Redis denylist / `revoked_before` marker.
* **Redis outage** — login fails closed (503). Denylist checks degrade to the 15-minute token lifetime
  and the global limiter fails open; both are logged.
* **Parallel refresh with the same token** is treated as reuse and revokes the family. That is safe,
  but a buggy client that retries refresh concurrently will be logged out.
* **Soft-deleted accounts keep their email reserved** (unique constraint) so a deleted address cannot
  be re-registered to inherit audit history.
