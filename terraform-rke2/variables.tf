variable "aws_region" {
  description = "AWS region where the RKE2 cluster is deployed"
  type        = string
  default     = "eu-west-3"
}

variable "project_name" {
  description = "Prefix used to name/tag all resources (and SSM parameter path)"
  type        = string
  default     = "k8s-escape-demo-rke2"
}

variable "vpc_cidr" {
  # Must NOT overlap with RKE2/Canal cluster-cidr (10.42.0.0/16) or service-cidr
  # (10.43.0.0/16). Otherwise the VPC DNS resolver (base-CIDR + 2) falls inside
  # the pod CIDR and CoreDNS forwards to itself -> CrashLoopBackOff.
  description = "CIDR block for the dedicated VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet hosting the RKE2 node"
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type for the RKE2 all-in-one node"
  type        = string
  default     = "t3.xlarge"
}

variable "root_volume_size_gb" {
  description = "Root volume size in GB"
  type        = number
  default     = 50
}

variable "allowed_admin_cidrs" {
  description = "CIDRs allowed to reach the K8s API (6443), ingress (80/443) and the NodePort range (30000-32767)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "rke2_version" {
  description = "RKE2 version to install (must be >= 1.31 for appArmorProfile support)"
  type        = string
  default     = "v1.31.2+rke2r1"
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair (optional — SSM Session Manager works without). Leave empty to skip."
  type        = string
  default     = ""
}
