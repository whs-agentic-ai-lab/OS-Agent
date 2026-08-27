data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_ami" "selected" {
  count = var.base_ami_id == "" ? 0 : 1

  most_recent = false
  owners      = ["099720109477"]

  filter {
    name   = "image-id"
    values = [var.base_ami_id]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*"]
  }
}
