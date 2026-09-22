variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  default     = "europe-west1"
}

variable "zone" {
  description = "GCP zone for the GKE cluster (single-zone deployment)"
  default     = "europe-west1-b"
}

variable "project_name" {
  description = "Project name used as prefix for all resources"
  default     = "k8s-escape-demo"
}

variable "cluster_name" {
  description = "GKE cluster name"
  default     = "gke-escape-demo"
}

variable "node_count" {
  description = "Number of nodes per zone in the node pool (regional cluster = 3 zones, so total nodes = 3 x this)"
  default     = 1
}

variable "node_machine_type" {
  description = "Machine type for GKE nodes (e2-standard-2 ~ t3.large)"
  default     = "e2-standard-2"
}

variable "node_disk_size" {
  description = "Boot disk size in GB for GKE nodes"
  default     = 30
}
