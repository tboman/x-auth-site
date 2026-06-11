output "service_urls" {
  description = "Cloud Run URLs per service (internal services are only reachable from the VPC)."
  value       = { for name, svc in google_cloud_run_v2_service.svc : name => svc.uri }
}

output "sql_instance_connection_name" {
  description = "Cloud SQL connection name (for cloud-sql-proxy / ad-hoc access)."
  value       = google_sql_database_instance.pg.connection_name
}

output "sql_private_ip" {
  value = google_sql_database_instance.pg.private_ip_address
}

output "redis_host" {
  value = "${google_redis_instance.xauth.host}:${google_redis_instance.xauth.port}"
}

output "artifact_repo" {
  description = "Docker repo for CI pushes."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.xauth.repository_id}"
}

output "auth_issuer" {
  value = local.auth_issuer
}
