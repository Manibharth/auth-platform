# What Terraform creates (GCP)

```mermaid
flowchart LR
  subgraph shared["envs/shared (once per project)"]
    AR[Artifact Registry<br/>auth-platform]
    WIF[Workload Identity Pool<br/>GitHub OIDC]
    DSA[Deployer SA<br/>run.developer, AR writer]
  end
  subgraph env["envs/staging and envs/production (module platform)"]
    RUN[Cloud Run service<br/>auth-platform-ENV]
    JOB[Cloud Run job<br/>alembic upgrade head]
    RSA[Runtime SA]
    VPC[VPC + subnet<br/>Direct VPC egress]
    SQL[(Cloud SQL<br/>PostgreSQL 16, private IP)]
    MEM[(Memorystore<br/>Redis 7.2)]
    SM[Secret Manager<br/>database-url, redis-url,<br/>jwt-private-key, mfa-encryption-key]
    MON[Cloud Monitoring<br/>5xx-rate + p95 alerts]
  end
  GH[GitHub Actions] -- OIDC --> WIF --> DSA
  DSA -- push image --> AR
  DSA -- deploy as --> RSA
  RUN & JOB -- run as --> RSA
  RSA -- reads --> SM
  RUN & JOB --> VPC --> SQL & MEM
  RUN -. metrics .-> MON
```

## Bootstrap order

```bash
# 0. state bucket (once)
gsutil mb -l europe-west6 gs://<project>-tfstate && gsutil versioning set on gs://<project>-tfstate

# 1. shared: APIs, registry, GitHub OIDC
cd infra/terraform/envs/shared
terraform init -backend-config="bucket=<project>-tfstate"
terraform apply -var project_id=<project> -var github_repository=<owner>/<repo>

# 2. push a first image (CI does this afterwards)
docker build -t <region>-docker.pkg.dev/<project>/auth-platform/auth-platform:bootstrap .
docker push    <region>-docker.pkg.dev/<project>/auth-platform/auth-platform:bootstrap

# 3. each environment: create secret containers, add key material out of band, then apply
cd ../staging
terraform init -backend-config="bucket=<project>-tfstate"
terraform apply -target=module.platform.google_secret_manager_secret.secret -var-file=terraform.tfvars
../../../../scripts/bootstrap_secrets.sh <project> staging
terraform apply -var-file=terraform.tfvars

# 4. GitHub repository variables for cd.yml
#    GCP_PROJECT_ID, GCP_REGION, GCP_ARTIFACT_REPO=auth-platform,
#    GCP_WIF_PROVIDER (shared output), GCP_DEPLOY_SA (shared output)
#    secrets: SMOKE_EMAIL, SMOKE_PASSWORD; environment "production" with required reviewers
```

Tear down after demos: `terraform destroy` in `production`, `staging`, then `shared`
(production has `deletion_protection = true`; set it to false first).

## AWS mapping (same image)

| Concern | GCP (this repo) | AWS equivalent |
|---|---|---|
| Container | Cloud Run | ECS Fargate behind an ALB |
| PostgreSQL | Cloud SQL | RDS |
| Redis | Memorystore | ElastiCache |
| Secrets | Secret Manager | Secrets Manager |
| Registry | Artifact Registry | ECR |
| CI identity | Workload Identity Federation | IAM role trusted for GitHub OIDC |
| Migrations | Cloud Run job | ECS one-off task (`run-task`) |
| Logs/metrics | Cloud Logging/Monitoring | CloudWatch |
