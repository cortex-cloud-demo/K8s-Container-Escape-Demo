provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

#######################
# VPC & NETWORKING
#######################

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name                 = "${var.project_name}-vpc"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "main"
    yor_trace            = "46097037-2df2-44a2-bf53-5958ad96c134"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name                 = "${var.project_name}-igw"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "main"
    yor_trace            = "a394bec8-0ab0-4d02-92d3-518ffd578346"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name                 = "${var.project_name}-public-rt"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "public"
    yor_trace            = "c5483b69-1057-419d-adc5-c8e391bf07b7"
  }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                        = "${var.project_name}-public-${count.index}"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                    = "1"
    git_commit                                  = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file                                    = "terraform-infra/main.tf"
    git_last_modified_at                        = "2026-03-31 13:11:42"
    git_last_modified_by                        = "cley@paloaltonetworks.com"
    git_modifiers                               = "cley"
    git_org                                     = "cortex-cloud-demo"
    git_repo                                    = "K8s-Container-Escape-Demo"
    yor_name                                    = "public"
    yor_trace                                   = "fe91caf7-1d08-46ed-b381-566f0f04361c"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

#######################
# ECR REPOSITORY
#######################

resource "aws_ecr_repository" "vuln_app" {
  name                 = "${var.project_name}/vuln-app"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name                 = "${var.project_name}-vuln-app"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "vuln_app"
    yor_trace            = "934befe2-1d5e-43e0-b1f2-dd1f17518934"
  }
}

#######################
# IAM - EKS CLUSTER
#######################

resource "aws_iam_role" "eks_cluster" {
  name = "${var.project_name}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  tags = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "eks_cluster"
    yor_trace            = "ba3c5d76-57e6-4a6e-a53c-656e4c584d4f"
  }
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

#######################
# IAM - EKS NODES
#######################

resource "aws_iam_role" "eks_nodes" {
  name = "${var.project_name}-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  tags = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "eks_nodes"
    yor_trace            = "dd05c228-1f8c-4138-8744-7520fa5f433a"
  }
}

resource "aws_iam_role_policy_attachment" "eks_worker_node" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "ecr_read" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Intentionally overprivileged - for demo purposes
resource "aws_iam_role_policy_attachment" "eks_node_ec2_full" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

#######################
# EKS CLUSTER
#######################

resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = aws_subnet.public[*].id
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy
  ]
  tags = {
    git_commit           = "791cb1d04c6fb07ca96504f84588f83d6040e6f8"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-04-01 16:24:39"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "main"
    yor_trace            = "1f0c3845-352a-422c-8efc-5d8c21cbe3e7"
  }
}

#######################
# LAUNCH TEMPLATE (GP3)
#######################

resource "aws_launch_template" "eks_nodes" {
  name_prefix = "${var.project_name}-node-"

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.node_volume_size
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      delete_on_termination = true
      encrypted             = false
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-node"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.project_name}-node-volume"
    }
  }
  tags = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "eks_nodes"
    yor_trace            = "56cd7896-d1d6-4b80-bf82-71071299c9df"
  }
}

#######################
# EKS NODE GROUP
#######################

resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.project_name}-nodes"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = aws_subnet.public[*].id

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  ami_type       = "AL2023_x86_64_STANDARD"
  instance_types = [var.node_instance_type]

  launch_template {
    id      = aws_launch_template.eks_nodes.id
    version = "$Latest"
  }

  tags = {
    Name                 = "${var.project_name}-node"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-03-31 13:11:42"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "main"
    yor_trace            = "8ca621dc-9d7b-4d73-86c8-4fbc68379a16"
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node,
    aws_iam_role_policy_attachment.eks_cni,
    aws_iam_role_policy_attachment.ecr_read,
    aws_iam_role_policy_attachment.eks_node_ec2_full
  ]
}

#######################
# EKS ACCESS - DASHBOARD OPERATOR
#######################

resource "aws_eks_access_entry" "dashboard_operator" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.dashboard_operator.arn
  type          = "STANDARD"
  tags = {
    git_commit           = "9e5d9a119a382e50dfaca29a8f6225d8242e423f"
    git_file             = "terraform-infra/main.tf"
    git_last_modified_at = "2026-04-02 07:07:56"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "dashboard_operator"
    yor_trace            = "59243e14-48bd-4789-b92d-d123ada4da62"
  }
}

resource "aws_eks_access_policy_association" "dashboard_operator_admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.dashboard_operator.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.dashboard_operator]
}
