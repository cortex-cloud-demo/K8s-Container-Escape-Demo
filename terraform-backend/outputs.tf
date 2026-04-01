output "bucket_name" {
  description = "S3 bucket name for Terraform state"
  value       = aws_s3_bucket.tfstate.id
}

output "region" {
  description = "AWS region"
  value       = var.region
}
