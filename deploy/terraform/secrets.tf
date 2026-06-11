# Per-service Postgres DSNs. The services consume these via the PG_DSN env
# var (pkg/pgxdb).
resource "google_secret_manager_secret" "pg_dsn" {
  for_each = local.services

  secret_id = "pg-dsn-${local.short[each.key]}"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "pg_dsn" {
  for_each = local.services

  secret = google_secret_manager_secret.pg_dsn[each.key].id
  secret_data = format(
    "postgres://%s:%s@%s:5432/%s?sslmode=require",
    google_sql_user.db[each.key].name,
    random_password.db[each.key].result,
    google_sql_database_instance.pg.private_ip_address,
    each.value.db,
  )
}

# Redis AUTH string for the services that use pkg/redisx.
resource "google_secret_manager_secret" "redis_auth" {
  secret_id = "redis-auth"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "redis_auth" {
  secret      = google_secret_manager_secret.redis_auth.id
  secret_data = google_redis_instance.xauth.auth_string
}

# RS256 signing key for authentication-service (ARCHITECTURE.md §10.1).
# jwtx.LoadOrGenerateKey reads the PEM from the JWT_SIGNING_KEY env var.
#
# NOTE: generating the key in Terraform puts the PEM in state — acceptable
# while state lives in a locked-down GCS bucket, but the phase-3 key-rotation
# work should move issuance to Cloud KMS and drop this resource.
resource "tls_private_key" "jwt_signing" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "google_secret_manager_secret" "jwt_signing_key" {
  secret_id = "jwt-signing-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "jwt_signing_key" {
  secret      = google_secret_manager_secret.jwt_signing_key.id
  secret_data = tls_private_key.jwt_signing.private_key_pem
}
