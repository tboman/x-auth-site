# Dedicated VPC: Cloud SQL and Memorystore live on private IPs; Cloud Run
# reaches them (and the internal-ingress services) through the connector.

resource "google_compute_network" "xauth" {
  name                    = "x-auth"
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "xauth" {
  name          = "x-auth-${var.region}"
  region        = var.region
  network       = google_compute_network.xauth.id
  ip_cidr_range = "10.10.0.0/24"
}

resource "google_vpc_access_connector" "xauth" {
  name          = "x-auth-connector"
  region        = var.region
  network       = google_compute_network.xauth.name
  ip_cidr_range = "10.8.0.0/28"
  min_instances = 2
  max_instances = 3

  depends_on = [google_project_service.apis]
}

# Cloud NAT: services run with egress=ALL_TRAFFIC (required so calls to the
# internal-ingress run.app services count as VPC traffic), which routes ALL
# outbound through the VPC — NAT restores internet egress (social-login
# providers, webhooks).
resource "google_compute_router" "xauth" {
  name    = "x-auth-router"
  region  = var.region
  network = google_compute_network.xauth.id
}

resource "google_compute_router_nat" "xauth" {
  name                               = "x-auth-nat"
  router                             = google_compute_router.xauth.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# Private services access — gives Cloud SQL and Memorystore private IPs on
# this VPC.
resource "google_compute_global_address" "private_services" {
  name          = "x-auth-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.xauth.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.xauth.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]

  depends_on = [google_project_service.apis]
}
