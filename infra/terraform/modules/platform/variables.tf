variable "project_id" { type = string }
variable "region" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production"
  }
}
variable "image" {
  type        = string
  description = "Initial image; CD owns the image afterwards (ignored on later applies)"
}
variable "public_base_url" {
  type    = string
  default = ""
}
variable "cors_origins" {
  type    = list(string)
  default = []
}
variable "db_tier" {
  type    = string
  default = "db-f1-micro"
}
variable "redis_memory_gb" {
  type    = number
  default = 1
}
variable "min_instances" {
  type    = number
  default = 0
}
variable "max_instances" {
  type    = number
  default = 4
}
variable "cpu" {
  type    = string
  default = "1"
}
variable "memory" {
  type    = string
  default = "512Mi"
}
variable "demo_email" {
  type    = string
  default = ""
}
variable "deletion_protection" {
  type    = bool
  default = true
}
variable "alert_email" { type = string }
variable "error_rate_threshold" {
  type        = number
  default     = 0.02
  description = "Fraction of requests answered 5xx over 5 minutes"
}
variable "p95_latency_threshold_ms" {
  type    = number
  default = 300
}
variable "deployer_service_account" {
  type        = string
  description = "Email of the CI deploy service account (from envs/shared)"
}
