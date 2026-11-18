output "service_url" { value = google_cloud_run_v2_service.api.uri }
output "service_name" { value = google_cloud_run_v2_service.api.name }
output "migrate_job" { value = google_cloud_run_v2_job.migrate.name }
output "runtime_service_account" { value = google_service_account.runtime.email }
output "jwt_secret_id" { value = google_secret_manager_secret.secret["jwt-private-key"].secret_id }
output "mfa_secret_id" { value = google_secret_manager_secret.secret["mfa-encryption-key"].secret_id }
