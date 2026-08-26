resource "aws_internet_gateway" "trial" {
  vpc_id = aws_vpc.trial.id

  tags = {
    Name = "${local.resource_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.trial.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.resource_prefix}-nat-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.trial.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.trial.id
  }

  tags = {
    Name = "${local.resource_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${local.resource_prefix}-nat-eip"
  }
}

resource "aws_nat_gateway" "trial" {
  allocation_id     = aws_eip.nat.id
  subnet_id         = aws_subnet.public.id
  connectivity_type = "public"

  tags = {
    Name = "${local.resource_prefix}-nat"
  }

  depends_on = [
    aws_internet_gateway.trial,
    aws_route_table_association.public,
  ]
}

resource "aws_route" "private_via_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.trial.id
}
