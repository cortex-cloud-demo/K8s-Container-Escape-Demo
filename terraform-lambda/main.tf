provider "aws" {
  region = var.region
}

#######################
# DATA SOURCES - EKS
#######################

# Look up the existing EKS cluster (deployed by terraform/)
data "aws_eks_cluster" "main" {
  name = var.cluster_name
}

#######################
# IAM - LAMBDA
#######################

resource "aws_iam_role" "containment_lambda" {
  name = "${var.project_name}-containment-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.containment_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_eks" {
  name = "${var.project_name}-lambda-eks-policy"
  role = aws_iam_role.containment_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters"
        ]
        Resource = data.aws_eks_cluster.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })
}

#######################
# IAM - LAMBDA INVOKER ROLE
#######################
#
# Scoped role for invoking the containment Lambda (least-privilege).
# Trust policy:
#   - Always: same AWS account (dashboard operator / playbook with operator credentials)
#   - Optionally: cross-account (Cortex XSIAM) if cortex_aws_account_id is set
#

data "aws_caller_identity" "current" {}

locals {
  # Same-account trust (always present)
  same_account_statement = {
    Sid    = "SameAccountAssumeRole"
    Effect = "Allow"
    Principal = {
      AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
    }
    Action = "sts:AssumeRole"
  }

  # Cross-account trust (only if cortex_aws_account_id is provided)
  cross_account_statement = var.cortex_aws_account_id != "" ? [{
    Sid    = "CortexCrossAccountAssumeRole"
    Effect = "Allow"
    Principal = {
      AWS = "arn:aws:iam::${var.cortex_aws_account_id}:root"
    }
    Action = "sts:AssumeRole"
    Condition = var.cortex_external_id != "" ? {
      StringEquals = {
        "sts:ExternalId" = var.cortex_external_id
      }
    } : {}
  }] : []
}

resource "aws_iam_role" "lambda_invoker" {
  name = "${var.project_name}-lambda-invoker"

  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat([local.same_account_statement], local.cross_account_statement)
  })

  max_session_duration = 3600

  tags = {
    Name = "${var.project_name}-lambda-invoker"
  }
}

resource "aws_iam_role_policy" "lambda_invoker_policy" {
  name = "${var.project_name}-lambda-invoker-policy"
  role = aws_iam_role.lambda_invoker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.containment.arn
    }]
  })
}

#######################
# IAM USER - CORTEX PLAYBOOK
#######################
#
# Dedicated IAM User with permanent credentials for Cortex playbook.
# Only permission: sts:AssumeRole on the lambda-invoker role.
#
# Flow:
#   Cortex playbook (permanent Access Key) → AssumeRole → lambda-invoker role → Lambda
#

resource "aws_iam_user" "cortex_playbook" {
  name = "${var.project_name}-cortex-playbook-user"

  tags = {
    Name    = "${var.project_name}-cortex-playbook-user"
    Purpose = "Cortex playbook - permanent credentials for Lambda invocation via AssumeRole"
  }
}

resource "aws_iam_access_key" "cortex_playbook" {
  user = aws_iam_user.cortex_playbook.name
}

resource "aws_iam_user_policy" "cortex_assume_role" {
  name = "${var.project_name}-cortex-assume-lambda-invoker"
  user = aws_iam_user.cortex_playbook.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.lambda_invoker.arn
    }]
  })
}

#######################
# EKS ACCESS FOR LAMBDA
#######################

resource "aws_eks_access_entry" "lambda" {
  cluster_name  = data.aws_eks_cluster.main.name
  principal_arn = aws_iam_role.containment_lambda.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "lambda_admin" {
  cluster_name  = data.aws_eks_cluster.main.name
  principal_arn = aws_iam_role.containment_lambda.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.lambda]
}

#######################
# LAMBDA FUNCTION
#######################

data "archive_file" "containment_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/containment"
  output_path = "${path.module}/../lambda/containment.zip"
}

resource "aws_lambda_function" "containment" {
  filename         = data.archive_file.containment_lambda.output_path
  function_name    = "${var.project_name}-containment"
  role             = aws_iam_role.containment_lambda.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.containment_lambda.output_base64sha256
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      EKS_CLUSTER_NAME = data.aws_eks_cluster.main.name
      AWS_REGION_NAME  = var.region
      TARGET_NAMESPACE = "vuln-app"
    }
  }

  tags = {
    Name = "${var.project_name}-containment"
  }
}
