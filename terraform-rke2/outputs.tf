output "instance_id" {
  description = "EC2 instance ID of the RKE2 node"
  value       = aws_instance.rke2.id
}

output "public_ip" {
  description = "Public IP (Elastic IP) of the RKE2 node"
  value       = aws_eip.rke2.public_ip
}

output "ssm_session_command" {
  description = "Command to open a shell on the node (no SSH needed)"
  value       = "aws ssm start-session --region ${var.aws_region} --target ${aws_instance.rke2.id}"
}

output "kubeconfig_fetch_command" {
  description = "Command to fetch the kubeconfig locally from SSM Parameter Store"
  value       = "aws ssm get-parameter --region ${var.aws_region} --name /${var.project_name}/kubeconfig --with-decryption --query Parameter.Value --output text"
}

output "kubernetes_api_endpoint" {
  description = "Kubernetes API endpoint (uses the public EIP)"
  value       = "https://${aws_eip.rke2.public_ip}:6443"
}

output "ingress_http_url" {
  description = "HTTP URL of the demo workloads via ingress-nginx (NodePort 30080)"
  value       = "http://${aws_eip.rke2.public_ip}:30080"
}

output "ssm_kubeconfig_param_name" {
  description = "SSM Parameter Store path holding the rewritten kubeconfig"
  value       = "/${var.project_name}/kubeconfig"
}
