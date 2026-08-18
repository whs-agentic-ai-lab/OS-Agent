# VPC + Private Subnet + Security Group 생성
# EC2는 Private Subnet에 두고 public IP는 주지 않는다.
# 대신 SSM(AWS 원격 관리 서비스)으로 접속할 수 있도록 VPC Endpoint를 둔다.

resource "aws_vpc" "trial" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.trial.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = var.availability_zone

  # public IP 없음
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-private-subnet"
  }
}

# Private subnet 전용 라우팅 테이블 (인터넷 게이트웨이로 향하는 default route 없음)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.trial.id

  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# 보안 그룹: 들어오는 트래픽(inbound)은 전부 차단. 접속은 SSM으로만 한다.
resource "aws_security_group" "trial_ec2" {
  name        = "${var.project_name}-ec2-sg"
  description = "Trial EC2 SG - no inbound, SSM managed only"
  vpc_id      = aws_vpc.trial.id

  egress {
    description = "HTTPS - for apt/docker pull package installs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP - some apt mirrors still use http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS - VPC internal, Amazon-provided DNS resolver only"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${var.project_name}-ec2-sg"
  }
}

# VPC Endpoint용 보안 그룹 (Trial EC2 SG에서의 HTTPS만 허용)
resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project_name}-vpce-sg"
  description = "SSM VPC Endpoint SG"
  vpc_id      = aws_vpc.trial.id

  ingress {
    description     = "HTTPS from Trial EC2 to SSM Endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.trial_ec2.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-vpce-sg"
  }
}

# SSM 접속용 VPC Endpoint 3개 (인터넷 없이도 SSM 사용 가능하게 해줌)
locals {
  ssm_endpoint_services = ["ssm", "ssmmessages", "ec2messages"]
}

resource "aws_vpc_endpoint" "ssm" {
  for_each = toset(local.ssm_endpoint_services)

  vpc_id              = aws_vpc.trial.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-${each.value}"
  }
}
