variable "project_id" {
  description = "GCP project that hosts the platform (same project as Firebase Hosting)."
  type        = string
  default     = "xauth-2026"
}

variable "region" {
  description = "Region for Cloud Run, Cloud SQL, Memorystore, and the VPC connector."
  type        = string
  default     = "europe-north1"
}

variable "db_tier" {
  description = "Cloud SQL machine tier. Bump to db-custom-* with HA for production load."
  type        = string
  default     = "db-f1-micro"
}

variable "db_availability_type" {
  description = "ZONAL for cost, REGIONAL for HA (ARCHITECTURE.md Appendix B prescribes HA in production)."
  type        = string
  default     = "ZONAL"
}

variable "redis_memory_size_gb" {
  description = "Memorystore capacity in GB."
  type        = number
  default     = 1
}

variable "redis_tier" {
  description = "BASIC for cost, STANDARD_HA for production."
  type        = string
  default     = "BASIC"
}

variable "max_instances" {
  description = "Cloud Run max instances per service."
  type        = number
  default     = 3
}

variable "min_instances" {
  description = "Cloud Run min instances per service. 0 = scale to zero (cold starts are cheap for these Go services)."
  type        = number
  default     = 0
}

variable "auth_public_url" {
  description = "Public issuer URL for authentication-service (e.g. https://auth.x-auth.com). Empty = use the deterministic run.app URL."
  type        = string
  default     = ""
}
