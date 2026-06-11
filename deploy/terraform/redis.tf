# Shared Redis (ARCHITECTURE.md §6.3, §10.5) — cross-replica rate limiting
# for transaction-service and authenticator-service via pkg/redisx.

resource "google_redis_instance" "xauth" {
  name           = "x-auth-redis"
  region         = var.region
  tier           = var.redis_tier
  memory_size_gb = var.redis_memory_size_gb
  redis_version  = "REDIS_7_0"

  authorized_network = google_compute_network.xauth.id
  auth_enabled       = true

  depends_on = [google_project_service.apis]
}
