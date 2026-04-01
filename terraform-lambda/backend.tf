terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # S3 backend - bucket created by scripts/setup-tf-backend.sh
  # Initialized dynamically via: terraform init -backend-config=...
  backend "s3" {}
}
