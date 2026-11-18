locals {
  name = "auth-platform-${var.environment}"
  labels = {
    app         = "auth-platform"
    environment = var.environment
    managed-by  = "terraform"
  }
}

# ---------------------------------------------------------------- network
resource "google_compute_network" "vpc" {
  name                    = local.name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "run" {
  name                     = "${local.name}-run"
  network                  = google_compute_network.vpc.id
  region                   = var.region
  ip_cidr_range            = var.environment == "production" ? "10.20.0.0/24" : "10.10.0.0/24"
  private_ip_google_access = true
}

# Private services access: Cloud SQL and Memorystore get private IPs only.
resource "google_compute_global_address" "private_services" {
  name          = "${local.name}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

# ---------------------------------------------------------------- PostgreSQL
resource "google_sql_database_instance" "pg" {
  name                = local.name
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = var.deletion_protection
  depends_on          = [google_service_networking_connection.private_services]

  settings {
    tier              = var.db_tier
    edition           = "ENTERPRISE"
    availability_type = var.environment == "production" ? "REGIONAL" : "ZONAL"
    user_labels       = local.labels

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = var.environment == "production"
    }
    database_flags {
      name  = "log_min_duration_statement"
      value = "500"
    }
    insights_config { query_insights_enabled = true }
  }
}

resource "google_sql_database" "app" {
  name     = "auth"
  instance = google_sql_database_instance.pg.name
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "google_sql_user" "app" {
  name     = "auth_app"
  instance = google_sql_database_instance.pg.name
  password = random_password.db.result
}

# ---------------------------------------------------------------- Redis
resource "google_redis_instance" "cache" {
  name               = local.name
  tier               = var.environment == "production" ? "STANDARD_HA" : "BASIC"
  memory_size_gb     = var.redis_memory_gb
  region             = var.region
  redis_version      = "REDIS_7_2"
  authorized_network = google_compute_network.vpc.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
  labels             = local.labels
  depends_on         = [google_service_networking_connection.private_services]
}

# ---------------------------------------------------------------- secrets
# DATABASE_URL and REDIS_URL are derived here. The JWT private key and the MFA
# encryption key are added out of band (scripts/bootstrap_secrets.sh), so they
# never appear in Terraform state.
resource "google_secret_manager_secret" "secret" {
  for_each  = toset(["database-url", "redis-url", "jwt-private-key", "mfa-encryption-key"])
  secret_id = "${local.name}-${each.key}"
  labels    = local.labels
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.secret["database-url"].id
  secret_data = format(
    "postgresql+asyncpg://%s:%s@%s:5432/%s",
    google_sql_user.app.name,
    random_password.db.result,
    google_sql_database_instance.pg.private_ip_address,
    google_sql_database.app.name,
  )
}

resource "google_secret_manager_secret_version" "redis_url" {
  secret      = google_secret_manager_secret.secret["redis-url"].id
  secret_data = "redis://${google_redis_instance.cache.host}:${google_redis_instance.cache.port}/0"
}

# ---------------------------------------------------------------- identities
resource "google_service_account" "runtime" {
  account_id   = "${local.name}-run"
  display_name = "Auth platform ${var.environment} runtime"
}

resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each  = google_secret_manager_secret.secret
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime" {
  for_each = toset(["roles/cloudsql.client", "roles/monitoring.metricWriter", "roles/cloudtrace.agent"])
  project  = var.project_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.runtime.email}"
}

# CI may deploy revisions that run as the runtime identity, nothing more.
resource "google_service_account_iam_member" "deployer_acts_as_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.deployer_service_account}"
}

# ---------------------------------------------------------------- Cloud Run
locals {
  plain_env = {
    ENVIRONMENT         = var.environment
    PUBLIC_BASE_URL     = var.public_base_url
    CORS_ORIGINS        = join(",", var.cors_origins)
    EMAIL_BACKEND       = "smtp"
    DEMO_EMAIL          = var.demo_email
    DEMO_READ_ONLY      = var.environment == "production" ? "true" : "false"
    FORWARDED_ALLOW_IPS = "*" # only Google's front end can reach the container
    OTEL_ENABLED        = "false"
    LOG_JSON            = "true"
    JWT_ISSUER          = "auth-platform-${var.environment}"
  }
  secret_env = {
    DATABASE_URL       = "database-url"
    REDIS_URL          = "redis-url"
    JWT_PRIVATE_KEY    = "jwt-private-key"
    MFA_ENCRYPTION_KEY = "mfa-encryption-key"
  }
}

resource "google_cloud_run_v2_service" "api" {
  name                = local.name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = var.deletion_protection
  labels              = local.labels

  template {
    service_account                  = google_service_account.runtime.email
    max_instance_request_concurrency = 80
    timeout                          = "30s"
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }
    containers {
      image = var.image
      ports { container_port = 8000 }
      resources {
        limits            = { cpu = var.cpu, memory = var.memory }
        cpu_idle          = true
        startup_cpu_boost = true
      }
      dynamic "env" {
        for_each = local.plain_env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.secret_env
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.secret[env.value].secret_id
              version = "latest"
            }
          }
        }
      }
      startup_probe {
        http_get { path = "/healthz" }
        period_seconds    = 2
        failure_threshold = 15
      }
      liveness_probe {
        http_get { path = "/healthz" }
        period_seconds = 15
      }
    }
  }

  lifecycle {
    # CD (cd.yml) owns the image and traffic split after the first apply.
    ignore_changes = [template[0].containers[0].image, traffic, client, client_version]
  }
  depends_on = [google_secret_manager_secret_iam_member.runtime]
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.api.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers" # a public API; authentication happens in the app
}

# Migrations run as a separate release step, never at app start.
resource "google_cloud_run_v2_job" "migrate" {
  name                = "auth-platform-migrate-${var.environment}"
  location            = var.region
  deletion_protection = var.deletion_protection
  labels              = local.labels

  template {
    template {
      service_account = google_service_account.runtime.email
      max_retries     = 0
      timeout         = "600s"
      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = google_compute_network.vpc.id
          subnetwork = google_compute_subnetwork.run.id
        }
      }
      containers {
        image   = var.image
        command = ["alembic", "upgrade", "head"]
        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }
        env {
          name  = "EMAIL_BACKEND"
          value = "smtp"
        }
        dynamic "env" {
          for_each = local.secret_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.secret[env.value].secret_id
                version = "latest"
              }
            }
          }
        }
      }
    }
  }
  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image, client, client_version]
  }
}

# ---------------------------------------------------------------- alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "${local.name} on-call"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "error_rate" {
  display_name          = "${local.name}: 5xx error rate above ${var.error_rate_threshold * 100}%"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.email.id]
  conditions {
    display_name = "5xx ratio"
    condition_monitoring_query_language {
      duration = "300s"
      query    = <<-MQL
        fetch cloud_run_revision
        | metric 'run.googleapis.com/request_count'
        | filter resource.service_name == '${google_cloud_run_v2_service.api.name}'
        | align rate(5m)
        | group_by [], [errors: sum(if(metric.response_code_class == '5xx', val(), 0)), total: sum(val())]
        | value [ratio: cast_units(div(errors, total), '1')]
        | condition ratio > ${var.error_rate_threshold}
      MQL
    }
  }
}

resource "google_monitoring_alert_policy" "latency" {
  display_name          = "${local.name}: p95 latency above ${var.p95_latency_threshold_ms} ms"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.email.id]
  conditions {
    display_name = "p95 request latency"
    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"${google_cloud_run_v2_service.api.name}\" AND metric.type = \"run.googleapis.com/request_latencies\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.p95_latency_threshold_ms
      duration        = "300s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_PERCENTILE_95"
        cross_series_reducer = "REDUCE_MAX"
      }
    }
  }
}
