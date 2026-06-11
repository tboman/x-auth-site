terraform {
  required_version = ">= 1.7"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.35"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Recommended: keep state in GCS once the bucket exists.
  # backend "gcs" {
  #   bucket = "xauth-2026-tfstate"
  #   prefix = "x-auth/services"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
