# NAT Gateway: EC2가 패키지 설치(apt, docker pull)를 하려면 인터넷이 필요해서 추가.
# EC2는 여전히 Private Subnet에 있고 public IP는 없음 — 나가는 트래픽만 NAT를 거쳐 인터넷으로 나간다.

variable "public_subnet_cidr" {
  description = "NAT Gateway가 위치할 Public Subnet CIDR"
  type        = string
  default     = "10.20.0.0/24"
}

resource "aws_internet_gateway" "trial" {
  vpc_id = aws_vpc.trial.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.trial.id
  cidr_block               = var.public_subnet_cidr
  availability_zone        = var.availability_zone
  map_public_ip_on_launch  = true

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.trial.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.trial.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-nat-eip"
  }
}

resource "aws_nat_gateway" "trial" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name = "${var.project_name}-nat"
  }

  depends_on = [aws_internet_gateway.trial]
}

# Private Subnet 라우팅 테이블(vpc.tf)에 NAT를 통한 아웃바운드 경로 추가
resource "aws_route" "private_via_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id          = aws_nat_gateway.trial.id
}
