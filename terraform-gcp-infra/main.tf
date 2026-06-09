provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_project" "current" {}

#######################
# VPC & NETWORKING
#######################

resource "google_compute_network" "main" {
  name                    = "${var.project_name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name          = "${var.project_name}-subnet"
  ip_cidr_range = "10.0.0.0/16"
  region        = var.region
  network       = google_compute_network.main.id

  # Secondary ranges required by GKE (pods + services)
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.1.0.0/16"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.2.0.0/16"
  }
}

resource "google_compute_firewall" "allow_internal" {
  name    = "${var.project_name}-allow-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.0.0.0/8"]
}

resource "google_compute_firewall" "allow_http" {
  name    = "${var.project_name}-allow-http"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["${var.project_name}-node"]
}

#######################
# ARTIFACT REGISTRY (= ECR)
#######################

resource "google_artifact_registry_repository" "vuln_app" {
  location      = var.region
  repository_id = "${var.project_name}-vuln-app"
  format        = "DOCKER"
  description   = "Vulnerable app container registry for demo"

  labels = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-gcp-infra_main_tf"
    git_last_modified_at = "2026-06-09_14_45_00"
    git_last_modified_by = "cley_paloaltonetworks_com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "k8s-container-escape-demo"
    yor_name             = "vuln_app"
    yor_trace            = "5abf1876-8c0d-4682-a3d1-ec8d264189e9"
  }
}

#######################
# VULNERABLE GCS BUCKET (= S3)
#######################
# Intentionally misconfigured — no encryption, no versioning, legacy ACLs enabled
# Note: allUsers IAM binding blocked by org-level publicAccessPrevention policy;
#       bucket remains misconfigured (no encryption, no versioning, uniform_bucket_level_access=false)

resource "google_storage_bucket" "vuln_data" {
  name          = "${var.project_name}-vuln-data-${data.google_project.current.number}"
  location      = var.region
  force_destroy = true

  # Intentional — allows legacy per-object ACLs
  uniform_bucket_level_access = false

  labels = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-gcp-infra_main_tf"
    git_last_modified_at = "2026-06-09_14_45_00"
    git_last_modified_by = "cley_paloaltonetworks_com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "k8s-container-escape-demo"
    yor_name             = "vuln_data"
    yor_trace            = "45fee0cc-a0e5-4ce8-9af5-442c00dd0293"
  }
}

#######################
# SERVICE ACCOUNT — GKE NODES (= EC2 IAM Role, intentionally overprivileged)
#######################

resource "google_service_account" "gke_nodes" {
  account_id   = "${var.project_name}-gke-nodes"
  display_name = "GKE Node Pool SA — intentionally overprivileged for demo"
}

resource "google_project_iam_member" "gke_nodes_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_storage" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

#######################
# GKE CLUSTER (= EKS Cluster)
#######################

resource "google_container_cluster" "main" {
  name     = var.cluster_name
  location = var.region

  network    = google_compute_network.main.name
  subnetwork = google_compute_subnetwork.main.name

  remove_default_node_pool = true
  initial_node_count       = 1

  # Intentional misconfigurations for demo
  enable_legacy_abac = true

  # Opt out of managed release channel so auto_upgrade = false is allowed on node pool
  release_channel {
    channel = "UNSPECIFIED"
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  deletion_protection = false

  resource_labels = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-gcp-infra_main_tf"
    git_last_modified_at = "2026-06-09_14_45_00"
    git_last_modified_by = "cley_paloaltonetworks_com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "k8s-container-escape-demo"
    yor_name             = "main"
    yor_trace            = "fc068fe4-d068-45c7-b0e4-69ece21aa29f"
  }
}

#######################
# GKE NODE POOL (= EKS Node Group)
#######################

resource "google_container_node_pool" "main" {
  name     = "${var.project_name}-nodes"
  location = var.region
  cluster  = google_container_cluster.main.name

  node_count = var.node_count

  node_config {
    machine_type    = var.node_machine_type
    disk_size_gb    = var.node_disk_size
    disk_type       = "pd-ssd"
    service_account = google_service_account.gke_nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    # Intentional — no Shielded Nodes, no Workload Identity
    shielded_instance_config {
      enable_secure_boot          = false
      enable_integrity_monitoring = false
    }

    # Intentional — legacy metadata endpoint enabled (like IMDS on AWS)
    metadata = {
      disable-legacy-endpoints = "false"
    }

    tags = ["${var.project_name}-node", "gke-node"]

    labels = {
      env     = "demo"
      purpose = "intentionally-vulnerable"
    }

    # Propagated to the underlying GCE VM instances (visible in Cortex Asset Inventory)
    resource_labels = {
      git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
      git_file             = "terraform-gcp-infra_main_tf"
      git_last_modified_at = "2026-06-09_14_45_00"
      git_last_modified_by = "cley_paloaltonetworks_com"
      git_modifiers        = "cley"
      git_org              = "cortex-cloud-demo"
      git_repo             = "k8s-container-escape-demo"
      yor_name             = "main"
      yor_trace            = "3ddcb453-9afa-4ffa-aa09-ec0c85936faf"
    }
  }

  management {
    auto_repair  = false
    auto_upgrade = false
  }

  depends_on = [
    google_project_iam_member.gke_nodes_editor,
    google_project_iam_member.gke_nodes_storage,
  ]
}

#######################
# SERVICE ACCOUNT — DASHBOARD OPERATOR (= IAM User + Access Key)
#######################

resource "google_service_account" "dashboard" {
  account_id   = "${var.project_name}-dashboard"
  display_name = "Dashboard operator SA"
}

resource "google_project_iam_member" "dashboard_gke" {
  project = var.project_id
  role    = "roles/container.admin"
  member  = "serviceAccount:${google_service_account.dashboard.email}"
}

resource "google_project_iam_member" "dashboard_artifact_registry" {
  project = var.project_id
  role    = "roles/artifactregistry.admin"
  member  = "serviceAccount:${google_service_account.dashboard.email}"
}

resource "google_project_iam_member" "dashboard_storage" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.dashboard.email}"
}

resource "google_project_iam_member" "dashboard_cloudfunctions" {
  project = var.project_id
  role    = "roles/cloudfunctions.admin"
  member  = "serviceAccount:${google_service_account.dashboard.email}"
}

resource "google_project_iam_member" "dashboard_iam" {
  project = var.project_id
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:${google_service_account.dashboard.email}"
}

# JSON key for the dashboard SA — equivalent to AWS Access Key
resource "google_service_account_key" "dashboard" {
  service_account_id = google_service_account.dashboard.name
}
