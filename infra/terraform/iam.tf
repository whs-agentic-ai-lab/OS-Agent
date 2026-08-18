# EC2용 IAM Role: SSM 관리 권한만 부여한다.
# Agent가 사용할 AWS 권한은 여기 포함하지 않는다.

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
  name               = "${var.project_name}-ec2-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

# SSM 관리(Session Manager, Run Command)에 필요한 AWS 관리형 정책만 부여
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.trial_ec2.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# 선택 사항: EC2 상태(CPU/메모리 등)를 CloudWatch로 보내야 할 때만 켠다 (기본은 꺼짐)
resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  count      = var.attach_cloudwatch_agent_policy ? 1 : 0
  role       = aws_iam_role.trial_ec2.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "trial_ec2" {
  name = "${var.project_name}-ec2-instance-profile"
  role = aws_iam_role.trial_ec2.name
}

data "aws_iam_policy_document" "backend_ecr_pull" {
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
    resources = [aws_ecr_repository.agent_backend.arn]
  }
}

resource "aws_iam_role_policy" "backend_ecr_pull" {
  name   = "${var.project_name}-backend-ecr-pull"
  role   = aws_iam_role.trial_ec2.id
  policy = data.aws_iam_policy_document.backend_ecr_pull.json
}

# 참고: Agent가 쓸 AWS 권한은 여기 없음. 필요해지면 별도로 검토해서 추가해야 한다.
