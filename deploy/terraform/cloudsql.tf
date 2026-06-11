# One PostgreSQL 16 instance, one database + user per service — the
# "PostgreSQL per service" model from ARCHITECTURE.md §6.2 / Appendix B at
# shared-instance cost. Split into per-service instances when load or an
# Enterprise tenant demands it.

resource "google_sql_database_instance" "pg" {
  name             = "x-auth-pg"
  database_version = "POSTGRES_16"
  region           = var.region

  settings {
    tier              = var.db_tier
    availability_type = var.db_availability_type

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.xauth.id
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }

  deletion_protection = true

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "db" {
  for_each = local.services

  name     = each.value.db
  instance = google_sql_database_instance.pg.name
}

resource "random_password" "db" {
  for_each = local.services

  length  = 32
  special = false # keeps the DSN free of URL-encoding surprises
}

resource "google_sql_user" "db" {
  for_each = local.services

  name     = "${local.short[each.key]}_user"
  instance = google_sql_database_instance.pg.name
  password = random_password.db[each.key].result
}
