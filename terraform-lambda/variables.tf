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
