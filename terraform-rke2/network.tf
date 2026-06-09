data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name                 = "${var.project_name}-vpc"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/network.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "this"
    yor_trace            = "976eb9e3-9888-46b4-860b-a647a46130ea"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name                 = "${var.project_name}-igw"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/network.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "this"
    yor_trace            = "3618884b-f336-490c-972e-503dc52bacaa"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name                 = "${var.project_name}-public"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/network.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "public"
    yor_trace            = "101fde21-b3a8-43f1-b6f8-b6de520e7ca0"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name                 = "${var.project_name}-public-rt"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/network.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "public"
    yor_trace            = "472a3174-7524-4bf7-91c5-0382d207493a"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "rke2" {
  name        = "${var.project_name}-sg"
  description = "K8s Container Escape demo - RKE2 all-in-one access"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "Kubernetes API"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
  }

  ingress {
    description = "Ingress HTTP (demo workloads)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
  }

  ingress {
    description = "Ingress HTTPS (demo workloads)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
  }

  ingress {
    description = "NodePort range (ingress-nginx + demo services)"
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
  }

  egress {
    description = "All egress (pull images, Cortex agent, updates)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name                 = "${var.project_name}-sg"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/network.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "rke2"
    yor_trace            = "9b510196-e04c-4873-9e7d-6ede61dec909"
  }
}
