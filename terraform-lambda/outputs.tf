output "containment_lambda_arn" {
  value = aws_lambda_function.containment.arn
}

output "containment_lambda_name" {
  value = aws_lambda_function.containment.function_name
}

output "lambda_role_arn" {
  value = aws_iam_role.containment_lambda.arn
}

output "lambda_invoker_role_arn" {
  value       = aws_iam_role.lambda_invoker.arn
  description = "IAM Role ARN to assume for scoped Lambda invocation (same-account + optional cross-account)"
}

output "cortex_user_name" {
  value = aws_iam_user.cortex_playbook.name
}

output "cortex_user_access_key_id" {
  value       = aws_iam_access_key.cortex_playbook.id
  description = "Permanent Access Key ID for the Cortex playbook user"
}

output "cortex_user_secret_access_key" {
  value       = aws_iam_access_key.cortex_playbook.secret
  sensitive   = true
  description = "Secret Access Key for the Cortex playbook user (use: terraform output -raw cortex_user_secret_access_key)"
}

output "cluster_name" {
  value = data.aws_eks_cluster.main.name
}

output "region" {
  value = var.region
}
