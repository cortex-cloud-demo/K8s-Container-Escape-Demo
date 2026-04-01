output "cluster_name" {
  value = aws_eks_cluster.main.name
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

output "containment_lambda_arn" {
  value = aws_lambda_function.containment.arn
}

output "containment_lambda_name" {
  value = aws_lambda_function.containment.function_name
}
