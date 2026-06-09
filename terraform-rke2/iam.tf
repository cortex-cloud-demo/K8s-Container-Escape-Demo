data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rke2" {
  name               = "${var.project_name}-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json

  tags = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/iam.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "rke2"
    yor_trace            = "bd93ce90-427c-4bf8-ac3b-2dc806174dc8"
  }
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.rke2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "rke2" {
  name = "${var.project_name}-profile"
  role = aws_iam_role.rke2.name

  tags = {
    git_commit           = "4bcffddfd7be2992bb534ba81c88740e95f22bab"
    git_file             = "terraform-rke2/iam.tf"
    git_last_modified_at = "2026-06-09 14:45:00"
    git_last_modified_by = "cley@paloaltonetworks.com"
    git_modifiers        = "cley"
    git_org              = "cortex-cloud-demo"
    git_repo             = "K8s-Container-Escape-Demo"
    yor_name             = "rke2"
    yor_trace            = "4f2f5367-219e-4010-9c1c-0640244dfbb2"
  }
}
