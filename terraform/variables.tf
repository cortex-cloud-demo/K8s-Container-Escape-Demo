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

variable "cluster_version" {
  description = "Kubernetes version"
  default     = "1.35"
}

variable "node_volume_size" {
  description = "EBS volume size in GB for EKS nodes"
  default     = 30
}

variable "node_instance_type" {
  description = "EC2 instance type for EKS nodes"
  default     = "t3.medium"
}
