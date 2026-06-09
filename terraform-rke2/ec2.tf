data "aws_ami" "ubuntu_2204" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_eip" "rke2" {
  domain = "vpc"

  tags = {
    Name                 = "${var.project_name}-eip"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/ec2.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "rke2"
    yor_trace            = "2184aedd-2069-4d21-901e-f05fa82ed614"
  }
}

# Minimal IAM policy: allow the instance to push the kubeconfig into SSM Parameter Store
data "aws_iam_policy_document" "ssm_param_write" {
  statement {
    actions = [
      "ssm:PutParameter",
      "ssm:GetParameter",
      "ssm:AddTagsToResource"
    ]
    resources = [
      "arn:aws:ssm:${var.aws_region}:*:parameter/${var.project_name}/*"
    ]
  }
}

resource "aws_iam_role_policy" "ssm_param_write" {
  name   = "${var.project_name}-ssm-param-write"
  role   = aws_iam_role.rke2.id
  policy = data.aws_iam_policy_document.ssm_param_write.json
}

resource "aws_instance" "rke2" {
  ami                    = data.aws_ami.ubuntu_2204.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.rke2.id]
  iam_instance_profile   = aws_iam_instance_profile.rke2.name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  root_block_device {
    volume_size = var.root_volume_size_gb
    volume_type = "gp3"
    encrypted   = true

    tags = {
      Name                 = "${var.project_name}-node-root"
      git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
      git_file             = "terraform-rke2/ec2.tf"
      git_last_modified_at = "2026-06-09 14:45:00"
      git_last_modified_by = "cley@paloaltonetworks.com"
      git_modifiers        = "cley"
      git_org              = "cortex-cloud-demo"
      git_repo             = "K8s-Container-Escape-Demo"
      yor_name             = "rke2"
      yor_trace            = "69fe2f84-eb97-4584-8574-e7db7dab64d3"
    }
  }

  user_data = templatefile("${path.module}/scripts/rke2-bootstrap.sh.tftpl", {
    public_ip    = aws_eip.rke2.public_ip
    public_dns   = "rke2.${var.project_name}.local"
    rke2_version = var.rke2_version
    aws_region   = var.aws_region
    project_name = var.project_name
  })

  user_data_replace_on_change = true

  tags = {
    Name                 = "${var.project_name}-node"
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/ec2.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "rke2"
    yor_trace            = "1334c5bb-f56f-458d-bead-3b57bb33dc23"
  }

  depends_on = [aws_iam_role_policy.ssm_param_write]
}

resource "aws_eip_association" "rke2" {
  instance_id   = aws_instance.rke2.id
  allocation_id = aws_eip.rke2.id
}
