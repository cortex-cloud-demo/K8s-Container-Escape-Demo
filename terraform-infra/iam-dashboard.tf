#######################
# IAM - DASHBOARD USER + ROLE
#######################
#
# Dedicated IAM User with permanent credentials for the dashboard.
# The user's only permission is sts:AssumeRole on the dashboard-operator role.
# The role contains all scoped permissions (EKS, ECR, S3, Lambda, VPC, IAM).
#
# Flow:
#   Dashboard user (permanent Access Key) → AssumeRole → dashboard-operator role
#
# Usage:
#   1. First `terraform apply` with admin credentials creates user + role
#   2. Use terraform outputs dashboard_user_access_key_id / dashboard_user_secret_access_key
#   3. Paste these permanent credentials in Dashboard Settings → AWS Credentials
#

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_iam_role" "dashboard_operator" {
  name = "${var.project_name}-dashboard-operator"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.dashboard_trusted_principal != "" ? var.dashboard_trusted_principal : "arn:aws:iam::${local.account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = var.dashboard_external_id != "" ? {
        StringEquals = {
          "sts:ExternalId" = var.dashboard_external_id
        }
      } : {}
    }]
  })

  max_session_duration = 14400 # 4 hours for long demo sessions

  tags = {
    Name                 = "${var.project_name}-dashboard-operator"
    Purpose              = "Demo dashboard operator role"
    git_commit           = "9e5d9a119a382e50dfaca29a8f6225d8242e423f"
    git_file             = "terraform-infra/iam-dashboard.tf"
    git_last_modified_at = "2026-04-02 07:07:56"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "dashboard_operator"
    yor_trace            = "ab917617-c5a0-4d58-9cec-24e9444b812b"
  }
}

# ── STS ──────────────────────────────────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_sts" {
  name = "${var.project_name}-dashboard-sts"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sts:GetCallerIdentity",
        "sts:GetAccessKeyInfo",
      ]
      Resource = "*"
    }]
  })
}

# ── EKS ──────────────────────────────────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_eks" {
  name = "${var.project_name}-dashboard-eks"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EKSClusterManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateCluster",
          "eks:DeleteCluster",
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:UpdateClusterConfig",
          "eks:UpdateClusterVersion",
          "eks:TagResource",
          "eks:UntagResource",
          "eks:ListTagsForResource",
        ]
        Resource = "arn:aws:eks:${var.region}:${local.account_id}:cluster/${var.cluster_name}"
      },
      {
        Sid    = "EKSNodeGroups"
        Effect = "Allow"
        Action = [
          "eks:CreateNodegroup",
          "eks:DeleteNodegroup",
          "eks:DescribeNodegroup",
          "eks:ListNodegroups",
          "eks:UpdateNodegroupConfig",
          "eks:UpdateNodegroupVersion",
          "eks:TagResource",
        ]
        Resource = [
          "arn:aws:eks:${var.region}:${local.account_id}:cluster/${var.cluster_name}",
          "arn:aws:eks:${var.region}:${local.account_id}:nodegroup/${var.cluster_name}/*/*",
        ]
      },
      {
        Sid    = "EKSAccessManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateAccessEntry",
          "eks:DeleteAccessEntry",
          "eks:DescribeAccessEntry",
          "eks:ListAccessEntries",
          "eks:ListAccessPolicies",
          "eks:AssociateAccessPolicy",
          "eks:DisassociateAccessPolicy",
        ]
        Resource = [
          "arn:aws:eks:${var.region}:${local.account_id}:cluster/${var.cluster_name}",
          "arn:aws:eks:${var.region}:${local.account_id}:access-entry/${var.cluster_name}/*/*",
        ]
      },
      {
        Sid    = "EKSAddons"
        Effect = "Allow"
        Action = [
          "eks:CreateAddon",
          "eks:DeleteAddon",
          "eks:DescribeAddon",
          "eks:DescribeAddonVersions",
          "eks:ListAddons",
          "eks:UpdateAddon",
        ]
        Resource = "arn:aws:eks:${var.region}:${local.account_id}:cluster/${var.cluster_name}"
      },
    ]
  })
}

# ── ECR ──────────────────────────────────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_ecr" {
  name = "${var.project_name}-dashboard-ecr"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRAuth"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRRepository"
        Effect = "Allow"
        Action = [
          "ecr:CreateRepository",
          "ecr:DeleteRepository",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchDeleteImage",
          "ecr:CompleteLayerUpload",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
          "ecr:GetRepositoryPolicy",
          "ecr:SetRepositoryPolicy",
          "ecr:DeleteRepositoryPolicy",
          "ecr:TagResource",
          "ecr:ListTagsForResource",
        ]
        Resource = "arn:aws:ecr:${var.region}:${local.account_id}:repository/${var.project_name}/*"
      },
    ]
  })
}

# ── S3 (Terraform State) ────────────────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_s3" {
  name = "${var.project_name}-dashboard-s3"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TFStateBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:GetBucketLocation",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging",
          "s3:GetObjectVersion",
          "s3:ListBucketVersions",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetBucketRequestPayment",
          "s3:GetBucketCORS",
          "s3:GetBucketLogging",
          "s3:GetLifecycleConfiguration",
          "s3:GetReplicationConfiguration",
          "s3:GetAccelerateConfiguration",
          "s3:GetBucketWebsite",
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-tfstate-${local.account_id}",
          "arn:aws:s3:::${var.project_name}-tfstate-${local.account_id}/*",
        ]
      },
      {
        Sid    = "TFStateBucketManagement"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:PutBucketVersioning",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
        ]
        Resource = "arn:aws:s3:::${var.project_name}-tfstate-${local.account_id}"
      },
    ]
  })
}

# ── Lambda ───────────────────────────────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_lambda" {
  name = "${var.project_name}-dashboard-lambda"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:GetFunctionCodeSigningConfig",
        "lambda:InvokeFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:ListFunctions",
        "lambda:ListVersionsByFunction",
        "lambda:GetPolicy",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:TagResource",
        "lambda:ListTags",
      ]
      Resource = "arn:aws:lambda:${var.region}:${local.account_id}:function:${var.project_name}-*"
    }]
  })
}

# ── IAM (Terraform-managed roles) ───────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_iam" {
  name = "${var.project_name}-dashboard-iam"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMRoleManagement"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:ListRoleTags",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:PassRole",
        ]
        Resource = "arn:aws:iam::${local.account_id}:role/${var.project_name}-*"
      },
      {
        Sid    = "IAMPolicyRead"
        Effect = "Allow"
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
        ]
        Resource = "*"
      },
    ]
  })
}

# ── EC2 / VPC (Terraform infrastructure) ────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_ec2_vpc" {
  name = "${var.project_name}-dashboard-ec2-vpc"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VPCManagement"
        Effect = "Allow"
        Action = [
          # VPC
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:DescribeVpcs",
          "ec2:ModifyVpcAttribute",
          "ec2:DescribeVpcAttribute",
          # Subnets
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:DescribeSubnets",
          "ec2:ModifySubnetAttribute",
          # Internet Gateway
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:DescribeInternetGateways",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          # Route Tables
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:DescribeRouteTables",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          # Security Groups
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          # NAT / EIP (if needed)
          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:DescribeAddresses",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:DescribeNatGateways",
          # Tags
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          # Launch Templates
          "ec2:CreateLaunchTemplate",
          "ec2:DeleteLaunchTemplate",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:CreateLaunchTemplateVersion",
          # Instances (EKS nodes)
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceTypes",
          # General
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeImages",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeVolumes",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.region
          }
        }
      },
    ]
  })
}

# ── CloudWatch Logs (Lambda) ────────────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_logs" {
  name = "${var.project_name}-dashboard-logs"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:DescribeLogGroups",
        "logs:PutRetentionPolicy",
        "logs:TagResource",
        "logs:ListTagsForResource",
      ]
      Resource = "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${var.project_name}-*"
    }]
  })
}

# ── ELB (K8s LoadBalancer services) ─────────────────────────────────────────

resource "aws_iam_role_policy" "dashboard_elb" {
  name = "${var.project_name}-dashboard-elb"
  role = aws_iam_role.dashboard_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeTags",
      ]
      Resource = "*"
    }]
  })
}

# ── IAM User (permanent credentials) ────────────────────────────────────────

resource "aws_iam_user" "dashboard" {
  name = "${var.project_name}-dashboard-user"

  tags = {
    Name                 = "${var.project_name}-dashboard-user"
    Purpose              = "Dashboard operator - permanent credentials for AssumeRole"
    git_commit           = "9e5d9a119a382e50dfaca29a8f6225d8242e423f"
    git_file             = "terraform-infra/iam-dashboard.tf"
    git_last_modified_at = "2026-04-02 07:07:56"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "dashboard"
    yor_trace            = "26170fdb-0a86-42c5-88e4-ec98edd23a4f"
  }
}

resource "aws_iam_access_key" "dashboard" {
  user = aws_iam_user.dashboard.name
}

resource "aws_iam_user_policy" "dashboard_assume_role" {
  name = "${var.project_name}-dashboard-assume-role"
  user = aws_iam_user.dashboard.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.dashboard_operator.arn
    }]
  })
}
