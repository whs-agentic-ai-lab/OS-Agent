resource "aws_vpc" "trial" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.resource_prefix}-vpc"
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.trial.id
  cidr_block              = var.private_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.resource_prefix}-private-subnet"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.trial.id

  tags = {
    Name = "${local.resource_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "trial_ec2" {
  name        = "${local.resource_prefix}-ec2-sg"
  description = "0826 OS experiment EC2 - no inbound, HTTPS and DNS egress only"
  vpc_id      = aws_vpc.trial.id

  egress {
    description = "HTTPS for ECR, fixed package artifacts, and Evidence API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "UDP DNS to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "TCP DNS fallback to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${local.resource_prefix}-ec2-sg"
  }
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.resource_prefix}-vpce-sg"
  description = "SSM VPC endpoint ingress from the experiment EC2 only"
  vpc_id      = aws_vpc.trial.id

  ingress {
    description     = "HTTPS from experiment EC2"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.trial_ec2.id]
  }

  tags = {
    Name = "${local.resource_prefix}-vpce-sg"
  }
}

locals {
  ssm_endpoint_services = toset(["ssm", "ssmmessages", "ec2messages"])
}

resource "aws_vpc_endpoint" "ssm" {
  for_each = local.ssm_endpoint_services

  vpc_id              = aws_vpc.trial.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${local.resource_prefix}-vpce-${each.value}"
  }
}
