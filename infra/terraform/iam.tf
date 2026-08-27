data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trial_ec2" {
  name               = "${local.resource_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.trial_ec2.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "trial_ec2" {
  name = "${local.resource_prefix}-ec2-instance-profile"
  role = aws_iam_role.trial_ec2.name
}

data "aws_iam_policy_document" "ecr_pull" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = [for repository in aws_ecr_repository.images : repository.arn]
  }
}

resource "aws_iam_role_policy" "ecr_pull" {
  name   = "${local.resource_prefix}-ecr-pull"
  role   = aws_iam_role.trial_ec2.id
  policy = data.aws_iam_policy_document.ecr_pull.json
}

data "aws_iam_policy_document" "collector_token" {
  count = var.enable_remote_evidence_sink ? 1 : 0

  statement {
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${var.collector_token_parameter_name}",
    ]
  }

  dynamic "statement" {
    for_each = var.collector_token_kms_key_arn == "" ? [] : [var.collector_token_kms_key_arn]
    iterator = kms_key

    content {
      actions   = ["kms:Decrypt"]
      resources = [kms_key.value]
    }
  }
}

resource "aws_iam_role_policy" "collector_token" {
  count = var.enable_remote_evidence_sink ? 1 : 0

  name   = "${local.resource_prefix}-collector-token-read"
  role   = aws_iam_role.trial_ec2.id
  policy = data.aws_iam_policy_document.collector_token[0].json
}
