output "containment_lambda_arn" {
  value = aws_lambda_function.containment.arn
}

output "containment_lambda_name" {
  value = aws_lambda_function.containment.function_name
}

output "lambda_role_arn" {
  value = aws_iam_role.containment_lambda.arn
}

output "cluster_name" {
  value = data.aws_eks_cluster.main.name
}

output "region" {
  value = var.region
}
