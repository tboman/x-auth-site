resource "google_artifact_registry_repository" "xauth" {
  repository_id = "x-auth"
  location      = var.region
  format        = "DOCKER"
  description   = "X-Auth service images (built by GitHub Actions)"

  depends_on = [google_project_service.apis]
}
