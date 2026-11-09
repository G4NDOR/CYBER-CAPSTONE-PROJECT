terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. Official Canonical Ubuntu 24.04 LTS Dynamic AMI Query
data "aws_ami" "ubuntu_noble" {
  most_recent = true
  owners      = ["099720109477"] # Canonical ID

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# 2. Registering Local SSH Key Pair in AWS
resource "aws_key_pair" "admin_key" {
  key_name   = "${var.project_name}-key"
  public_key = file(var.admin_ssh_key_path)
}

# 3. Dual-Stack VPC (IPv4 + Free /56 IPv6 Block)
resource "aws_vpc" "main" {
  cidr_block                       = "10.100.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# 4. Gateways
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project_name}-igw"
  }
}

# $0.00 Egress-Only IGW for Private Subnet outbound IPv6
resource "aws_egress_only_internet_gateway" "eigw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project_name}-eigw"
  }
}

# 5. Subnets
# Public Subnet (Hosts Bastion)
resource "aws_subnet" "public" {
  vpc_id                          = aws_vpc.main.id
  cidr_block                      = "10.100.1.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, 1)
  assign_ipv6_address_on_creation = true
  map_public_ip_on_launch         = true
  availability_zone               = "${var.aws_region}a"

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

# Private Subnet (Hosts k3s Application Node)
resource "aws_subnet" "private" {
  vpc_id                          = aws_vpc.main.id
  cidr_block                      = "10.100.2.0/24"
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, 2)
  assign_ipv6_address_on_creation = true
  map_public_ip_on_launch         = false # No public IPv4 (saves money & increases security)
  availability_zone               = "${var.aws_region}a"

  tags = {
    Name = "${var.project_name}-private-subnet"
  }
}

# 6. Route Tables
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main.id

  # Outbound IPv6 routing via free Egress-Only IGW
  route {
    ipv6_cidr_block        = "::/0"
    egress_only_gateway_id = aws_egress_only_internet_gateway.eigw.id
  }

  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private_rt.id
}

# 7. Security Groups & Inter-Node Referencing
# Bastion SG (Public Facing)
resource "aws_security_group" "sg_bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "Allows SSH ingress only to the jump host"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from allowed admin IPs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_ipv4
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Application Node SG (Private Facing)
resource "aws_security_group" "sg_app_node" {
  name        = "${var.project_name}-app-sg"
  description = "Internal security group for k3s application node"
  vpc_id      = aws_vpc.main.id

  # Strict SSH: Only accept connections originating from the Bastion SG
  ingress {
    description     = "SSH exclusively from Bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.sg_bastion.id]
  }

  # Inbound HTTP/HTTPS for Web Dashboard via IPv6
  ingress {
    description      = "Dashboard HTTP (IPv6)"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "Dashboard HTTPS (IPv6)"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# 8. EC2 Instances
# Bastion Host (Public Subnet)
resource "aws_instance" "bastion" {
  ami                    = data.aws_ami.ubuntu_noble.id
  instance_type          = var.bastion_instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.sg_bastion.id]
  key_name               = aws_key_pair.admin_key.key_name

  root_block_device {
    volume_size           = 8
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "${var.project_name}-bastion"
  }
}

# Application & k3s Core Node (Private Subnet)
resource "aws_instance" "app_node" {
  ami                    = data.aws_ami.ubuntu_noble.id
  instance_type          = var.app_node_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.sg_app_node.id]
  key_name               = aws_key_pair.admin_key.key_name

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  # Minimal user_data: ensures python3 and minimal dependencies exist for Ansible
  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install -y python3 python3-pip
              EOF

  tags = {
    Name = "${var.project_name}-app-node"
  }
}

# 9. S3 Telemetry Bucket with Lifecycle Cost Rule
resource "aws_s3_bucket" "telemetry" {
  bucket_prefix = "ortsoc-telemetry-"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "telemetry_access" {
  bucket = aws_s3_bucket.telemetry.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "telemetry_retention" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    id     = "expire-alerts-14-days"
    status = "Enabled"
    
    # empty filter block so it targets all objects in the bucket
    filter {}

    expiration {
      days = 14
    }
  }
}