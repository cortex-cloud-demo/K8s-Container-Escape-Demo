# Using local backend for simplicity in demo context
# For production, use S3 backend:
# terraform {
#   backend "s3" {
#     bucket = "your-terraform-state-bucket"
#     key    = "k8s-escape-demo/terraform.tfstate"
#     region = "eu-west-3"
#   }
# }

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
