#######################
# LAMBDA - CONTAINMENT
#######################

# IAM Role for Lambda
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

# CloudWatch Logs
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.containment_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# EKS access for the Lambda
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
        Resource = aws_eks_cluster.main.arn
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

# EKS access entry for Lambda role (allows kubectl operations)
resource "aws_eks_access_entry" "lambda" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.containment_lambda.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "lambda_admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.containment_lambda.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.lambda]
}

# Package Lambda code
data "archive_file" "containment_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/containment"
  output_path = "${path.module}/../lambda/containment.zip"
}

# Lambda function
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
      EKS_CLUSTER_NAME = aws_eks_cluster.main.name
      AWS_REGION_NAME  = var.region
      TARGET_NAMESPACE = "vuln-app"
    }
  }

  tags = {
    Name = "${var.project_name}-containment"
  }
}
