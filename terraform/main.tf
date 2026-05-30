provider "aws" {
  region = var.aws_region
}

# Secure VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "devsecops-vpc"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Public Subnet (For Application Load Balancer or Web Server)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "devsecops-public-subnet"
  }
}

# Private Subnet (Where EC2 should reside in a multi-tier app, but for simplicity of this single instance we deploy in public subnet with restricted access, or keep it private and route via NAT. Let's make it a public subnet with restricted Security Group for simplicity, but strictly block inbound SSH)
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "devsecops-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "devsecops-public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Least-Privilege Security Group
# Restricts access to standard web traffic (HTTP/HTTPS)
# Inbound SSH (Port 22) is completely disabled. Shell access is handled securely via AWS SSM.
resource "aws_security_group" "web_sg" {
  name        = "devsecops-web-sg"
  description = "Allows only HTTP/HTTPS inbound traffic and restricted outbound"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow Flask Custom Port (Local testing/forwarding)"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

      # VULNERABILITY_IAC_START
  # VULNERABILITY_IAC_END

  egress {
    description = "Allow all outbound traffic (Needed for updates, installing packages, SSM)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "devsecops-sg"
  }
}

# Secure EC2 Instance
resource "aws_instance" "web_app" {
  ami                  = var.ami_id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  
  # Attach the IAM Instance Profile for secure SSM access
  iam_instance_profile = aws_iam_instance_profile.ec2_ssm_profile.name

  # Encrypted root block device is a security requirement
  root_block_device {
    encrypted   = true
    volume_size = 20
    volume_type = "gp3"
  }

  # User data to bootstrap the secure Flask app
  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install -y python3-pip python3-venv git
              
              # Create dedicated application user (Never run as root!)
              useradd -m -s /bin/bash webapp
              
              cd /home/webapp
              git clone https://github.com/${var.github_repo}.git app
              cd app/app
              
              python3 -m venv venv
              source venv/bin/activate
              pip3 install -r requirements.txt
              
              # Run Gunicorn as the daemon process listening on port 5000
              chown -R webapp:webapp /home/webapp
              sudo -u webapp bash -c "source venv/bin/activate && gunicorn -w 4 -b 0.0.0.0:5000 app:app --daemon"
              EOF

  tags = {
    Name        = "devsecops-secure-app"
    Environment = "Production"
  }
}
