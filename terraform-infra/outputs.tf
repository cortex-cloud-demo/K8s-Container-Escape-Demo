output "cluster_name" {
  value = aws_eks_cluster.main.name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "ecr_repository_url" {
  value = aws_ecr_repository.vuln_app.repository_url
}

output "ecr_repository_name" {
  value = aws_ecr_repository.vuln_app.name
}

output "region" {
  value = var.region
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --name ${aws_eks_cluster.main.name} --region ${var.region}"
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "dashboard_operator_role_arn" {
  value       = aws_iam_role.dashboard_operator.arn
  description = "IAM Role ARN for the dashboard operator (assume this role instead of using admin credentials)"
}

output "dashboard_operator_role_name" {
  value = aws_iam_role.dashboard_operator.name
}

output "dashboard_user_name" {
  value = aws_iam_user.dashboard.name
}

output "dashboard_user_access_key_id" {
  value       = aws_iam_access_key.dashboard.id
  description = "Permanent Access Key ID for the dashboard user (paste in Dashboard Settings)"
}

output "dashboard_user_secret_access_key" {
  value       = aws_iam_access_key.dashboard.secret
  sensitive   = true
  description = "Secret Access Key for the dashboard user (use: terraform output -raw dashboard_user_secret_access_key)"
}

