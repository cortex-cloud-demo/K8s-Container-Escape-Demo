variable "region" {
  description = "AWS region"
  default     = "eu-west-3"
}

variable "project_name" {
  description = "Project name used as prefix for all resources"
  default     = "k8s-escape-demo"
}

variable "cluster_name" {
  description = "EKS cluster name"
  default     = "eks-escape-demo"
}

variable "cortex_aws_account_id" {
  description = "AWS Account ID used by Cortex XSIAM for cross-account Lambda invocation (leave empty to skip cross-account role creation)"
  type        = string
  default     = ""
}

variable "cortex_external_id" {
  description = "External ID for STS AssumeRole (provided by Cortex XSIAM configuration)"
  type        = string
  default     = ""
  sensitive   = true
}
