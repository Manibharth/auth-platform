# One-time, project-wide resources: APIs, image registry, GitHub OIDC trust, deploy identity.
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
  backend "gcs" {
    prefix = "auth-platform/shared"
    # bucket is passed at init: terraform init -backend-config="bucket=<state-bucket>"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "europe-west6" # Zürich; use asia-south1 (Mumbai) or asia-south2 (Delhi) for India
}
variable "github_repository" {
  type        = string
  description = "owner/name of the repository allowed to deploy"
}

resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com", "sqladmin.googleapis.com", "redis.googleapis.com",
    "secretmanager.googleapis.com", "artifactregistry.googleapis.com", "compute.googleapis.com",
    "servicenetworking.googleapis.com", "iamcredentials.googleapis.com", "sts.googleapis.com",
    "monitoring.googleapis.com", "cloudtrace.googleapis.com",
  ])
  service            = each.key
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "images" {
  repository_id = "auth-platform"
  location      = var.region
  format        = "DOCKER"
  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions { keep_count = 30 }
  }
  depends_on = [google_project_service.apis]
}

# ---------------------------------------------------------------- GitHub OIDC (no stored keys)
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  # Only this repository's main branch (and its deployment environments) may assume the identity.
  attribute_condition = "assertion.repository == \"${var.github_repository}\" && (assertion.ref == \"refs/heads/main\" || assertion.sub.startsWith(\"repo:${var.github_repository}:environment:\"))"
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}

resource "google_service_account" "deployer" {
  account_id   = "auth-platform-deployer"
  display_name = "GitHub Actions deployer"
}

resource "google_service_account_iam_member" "wif" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

resource "google_project_iam_member" "deployer" {
  for_each = toset(["roles/run.developer"])
  project  = var.project_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_artifact_registry_repository_iam_member" "deployer_push" {
  repository = google_artifact_registry_repository.images.name
  location   = var.region
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deployer.email}"
}

output "workload_identity_provider" { value = google_iam_workload_identity_pool_provider.github.name }
output "deployer_service_account" { value = google_service_account.deployer.email }
output "image_repository" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}/auth-platform"
}
