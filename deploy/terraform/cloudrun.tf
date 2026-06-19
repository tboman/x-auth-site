# Service topology from ARCHITECTURE.md §3.1 / Appendix B and the Makefile
# run targets. Public services take internet traffic; internal services are
# reachable only from the VPC (callers run with egress=ALL_TRAFFIC so their
# requests arrive via the connector).
#
# Service-to-service auth, stage 1: network isolation (internal ingress)
# stands in for the mesh mTLS of ARCHITECTURE.md §10.3 — Cloud Run terminates
# TLS and doesn't expose peer certs. Revisit when moving to GKE (Appendix B
# end state) or teach the HTTP clients to attach IAM ID tokens.

locals {
  service_names = [
    "transaction-service",
    "risk-service",
    "authentication-service",
    "authenticator-service",
    "persona-service",
    "pool-service",
    "broker-service",
    "grant-service",
    "fido-service",
  ]

  short = {
    "transaction-service"    = "txn"
    "risk-service"           = "risk"
    "authentication-service" = "auth"
    "authenticator-service"  = "authr"
    "persona-service"        = "persona"
    "pool-service"           = "pool"
    "broker-service"         = "broker"
    "grant-service"          = "grant"
    "fido-service"           = "fido"
  }

  # Deterministic run.app URLs — avoids resource self-references in for_each.
  url = {
    for name in local.service_names :
    name => "https://${name}-${data.google_project.current.number}.${var.region}.run.app"
  }

  auth_issuer = var.auth_public_url != "" ? var.auth_public_url : local.url["authentication-service"]

  services = {
    "transaction-service" = {
      port   = 8080
      public = true
      db     = "txn_db"
      redis  = true
      env = {
        RISK_SERVICE_URL           = local.url["risk-service"]
        AUTHENTICATION_SERVICE_URL = local.url["authentication-service"]
        AUTHENTICATOR_SERVICE_URL  = local.url["authenticator-service"]
      }
    }
    "risk-service" = {
      port   = 8081
      public = false
      db     = "risk_db"
      redis  = false
      env    = {}
    }
    "authentication-service" = {
      port   = 8082
      public = true
      db     = "auth_db"
      redis  = false
      env = {
        AUTHENTICATOR_SERVICE_URL = local.url["authenticator-service"]
        AUTH_ISSUER               = local.auth_issuer
      }
    }
    "authenticator-service" = {
      port   = 8083
      public = false
      db     = "authr_db"
      redis  = true
      env    = {}
    }
    "persona-service" = {
      port   = 8180
      public = false
      db     = "persona_db"
      redis  = false
      env    = {}
    }
    "pool-service" = {
      port   = 8181
      public = false
      db     = "pool_db"
      redis  = false
      env    = {}
    }
    "broker-service" = {
      port   = 8182
      public = true
      db     = "broker_db"
      redis  = false
      env = {
        PERSONA_SERVICE_URL = local.url["persona-service"]
        POOL_SERVICE_URL    = local.url["pool-service"]
        GRANT_SERVICE_URL   = local.url["grant-service"]
      }
    }
    "grant-service" = {
      port   = 8183
      public = false
      db     = "grant_db"
      redis  = false
      env    = {}
    }
    # Public FIDO MDS risk API (fido.x-auth.com). Redis backs the shared blob
    # cache + rate limiter. Domain mapping is a manual post-apply step — see
    # deploy/terraform/README.md.
    "fido-service" = {
      port   = 8184
      public = true
      db     = "fido_db"
      redis  = true
      env    = {}
    }
  }

  # CI owns the image tag; Terraform deploys a placeholder on first apply and
  # ignores image changes afterwards (lifecycle below).
  placeholder_image = "us-docker.pkg.dev/cloudrun/container/hello"
}

resource "google_service_account" "run" {
  for_each = local.services

  account_id   = "run-${local.short[each.key]}"
  display_name = "Cloud Run ${each.key}"
}

resource "google_secret_manager_secret_iam_member" "pg_dsn" {
  for_each = local.services

  secret_id = google_secret_manager_secret.pg_dsn[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run[each.key].email}"
}

resource "google_secret_manager_secret_iam_member" "redis_auth" {
  for_each = { for name, svc in local.services : name => svc if svc.redis }

  secret_id = google_secret_manager_secret.redis_auth.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run[each.key].email}"
}

resource "google_secret_manager_secret_iam_member" "jwt_signing_key" {
  secret_id = google_secret_manager_secret.jwt_signing_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run["authentication-service"].email}"
}

resource "google_cloud_run_v2_service" "svc" {
  for_each = local.services

  name     = each.key
  location = var.region
  ingress  = each.value.public ? "INGRESS_TRAFFIC_ALL" : "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.run[each.key].email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    vpc_access {
      connector = google_vpc_access_connector.xauth.id
      egress    = "ALL_TRAFFIC"
    }

    containers {
      image = local.placeholder_image

      ports {
        container_port = each.value.port
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "256Mi"
        }
      }

      env {
        name  = "SERVICE_NAME"
        value = each.key
      }

      env {
        name = "PG_DSN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.pg_dsn[each.key].secret_id
            version = "latest"
          }
        }
      }

      dynamic "env" {
        for_each = each.value.env
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = each.value.redis ? [1] : []
        content {
          name  = "REDIS_ADDR"
          value = "${google_redis_instance.xauth.host}:${google_redis_instance.xauth.port}"
        }
      }

      dynamic "env" {
        for_each = each.value.redis ? [1] : []
        content {
          name = "REDIS_PASSWORD"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.redis_auth.secret_id
              version = "latest"
            }
          }
        }
      }

      dynamic "env" {
        for_each = each.key == "authentication-service" ? [1] : []
        content {
          name = "JWT_SIGNING_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.jwt_signing_key.secret_id
              version = "latest"
            }
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
        }
      }

      liveness_probe {
        http_get {
          path = "/healthz"
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [
    google_project_service.apis,
    google_secret_manager_secret_version.pg_dsn,
    google_secret_manager_secret_version.redis_auth,
    google_secret_manager_secret_version.jwt_signing_key,
    google_secret_manager_secret_iam_member.pg_dsn,
    google_secret_manager_secret_iam_member.redis_auth,
    google_secret_manager_secret_iam_member.jwt_signing_key,
  ]
}

# Public services accept anonymous traffic; internal services rely on
# internal-only ingress for access control (stage 1 — see header comment).
resource "google_cloud_run_v2_service_iam_member" "invoker" {
  for_each = local.services

  name     = google_cloud_run_v2_service.svc[each.key].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# One migration job per service. CI updates the image (built from
# deploy/docker/Dockerfile.migrate) and executes the jobs before rolling out
# new service revisions.
resource "google_cloud_run_v2_job" "migrate" {
  for_each = local.services

  name     = "migrate-${local.short[each.key]}"
  location = var.region

  template {
    template {
      service_account = google_service_account.run[each.key].email
      max_retries     = 1

      vpc_access {
        connector = google_vpc_access_connector.xauth.id
        egress    = "ALL_TRAFFIC"
      }

      containers {
        image   = "migrate/migrate:v4.17.1" # placeholder; CI swaps in the real migrations image
        command = ["/bin/sh", "-c"]
        args    = ["migrate -path /migrations/$${SERVICE} -database \"$${PG_DSN}\" up"]

        env {
          name  = "SERVICE"
          value = each.key
        }

        env {
          name = "PG_DSN"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.pg_dsn[each.key].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [
    google_secret_manager_secret_version.pg_dsn,
    google_secret_manager_secret_iam_member.pg_dsn,
  ]
}
