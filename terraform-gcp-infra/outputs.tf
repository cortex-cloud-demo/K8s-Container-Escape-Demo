output "cluster_name" {
  value = google_container_cluster.main.name
}

output "region" {
  value = var.region
}

output "project_id" {
  value = var.project_id
}

output "cluster_endpoint" {
  value = google_container_cluster.main.endpoint
}

output "artifact_registry_url" {
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.vuln_app.repository_id}"
  description = "Full Docker registry URL — use as image prefix (equivalent to ECR URL)"
}

output "artifact_registry_repository_id" {
  value = google_artifact_registry_repository.vuln_app.repository_id
}

output "vuln_data_bucket_name" {
  value       = google_storage_bucket.vuln_data.name
  description = "Intentionally public GCS bucket name (equivalent to S3 vuln-data bucket)"
}

output "dashboard_sa_email" {
  value       = google_service_account.dashboard.email
  description = "Dashboard operator service account email"
}

output "dashboard_sa_key" {
  value       = base64decode(google_service_account_key.dashboard.private_key)
  sensitive   = true
  description = "Dashboard operator SA JSON key — paste in Dashboard Settings > GCP (use: terraform output -raw dashboard_sa_key)"
}

output "kubeconfig_command" {
  value = "gcloud container clusters get-credentials ${google_container_cluster.main.name} --region ${var.region} --project ${var.project_id}"
}

output "project_number" {
  value = data.google_project.current.number
}
