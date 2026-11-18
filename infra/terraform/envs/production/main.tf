terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  backend "gcs" {
    prefix = "auth-platform/production"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "europe-west6"
}
variable "image" { type = string }
variable "alert_email" { type = string }
variable "deployer_service_account" { type = string }
variable "public_base_url" {
  type    = string
  default = ""
}
variable "demo_email" {
  type    = string
  default = "demo@example.com"
}

module "platform" {
  source                   = "../../modules/platform"
  project_id               = var.project_id
  region                   = var.region
  environment              = "production"
  image                    = var.image
  alert_email              = var.alert_email
  deployer_service_account = var.deployer_service_account
  public_base_url          = var.public_base_url
  demo_email               = var.demo_email
  min_instances            = 1
  max_instances            = 10
  db_tier                  = "db-custom-1-3840"
  deletion_protection      = true
}

output "service_url" { value = module.platform.service_url }
output "jwt_secret_id" { value = module.platform.jwt_secret_id }
output "mfa_secret_id" { value = module.platform.mfa_secret_id }
