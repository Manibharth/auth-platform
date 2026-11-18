# Workflow review checklist

Run through this for every change to `.github/workflows/` (OWASP "software and data integrity").

- [ ] Every third-party action is pinned to a full commit SHA with the version in a comment.
- [ ] Workflow-level `permissions:` is the minimum (`contents: read`); `id-token: write` only where OIDC is used.
- [ ] No long-lived cloud credentials: GCP access is via Workload Identity Federation only.
- [ ] `pull_request_target` is not used; untrusted PR code never runs with secrets.
- [ ] No `${{ github.event.* }}` user-controlled values are interpolated directly into `run:` scripts.
- [ ] Production deploy uses the `production` environment with required reviewers.
- [ ] The image deployed to production is the same digest that passed staging (built once in `cd.yml`).
- [ ] Migrations run as a separate job step before traffic moves.
- [ ] Smoke test failure triggers rollback to the previous revision.
- [ ] Dependabot covers `github-actions`, `uv`, `docker` and `terraform`.
- [ ] Branch protection on `main`: CI required, one review (self-review with this checklist for solo work).
