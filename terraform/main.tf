# terraform/main.tf
# Infrastructure AWS pour Next-Gen DevSecOps
# EC2 t2.micro (Free Tier) dans eu-west-3 (Paris)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-3"
}

# Security Group — règles réseau
resource "aws_security_group" "nextgen_sg" {
  name        = "nextgen-devsecops-sg"
  description = "Security group for Next-Gen DevSecOps"

  # Port 8000 — Backend FastAPI
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Port 22 — SSH (accès à l'instance)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Port 80 — HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Sortie — tout autoriser
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "nextgen-sg"
    Project = "PFS-2026"
  }
}

# Clé SSH pour accéder à l'instance
resource "aws_key_pair" "nextgen_key" {
  key_name   = "nextgen-key"
  public_key = file("~/.ssh/nextgen_key.pub")
}

# Instance EC2 — t2.micro Free Tier
resource "aws_instance" "nextgen_backend" {
  ami                    = "ami-011fc4a229f0661be"
  instance_type          = "t3.micro"
  key_name               = aws_key_pair.nextgen_key.key_name
  vpc_security_group_ids = [aws_security_group.nextgen_sg.id]
  monitoring             = true

  # Script de démarrage automatique
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y python3 python3-pip git
    pip3 install fastapi uvicorn python-jose bcrypt groq PyGithub prometheus-fastapi-instrumentator python-dotenv
    git clone https://github.com/bgoussama/next-gen-devsecops.git /app
    cd /app/backend
    nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 &
  EOF

  tags = {
    Name    = "nextgen-devsecops-backend"
    Project = "PFS-2026"
  }
}

# IP publique fixe
resource "aws_eip" "nextgen_ip" {
  instance = aws_instance.nextgen_backend.id
  domain   = "vpc"
}

# Afficher l'IP publique après création
output "backend_url" {
  value       = "http://${aws_eip.nextgen_ip.public_ip}:8000"
  description = "URL du backend déployé sur AWS"
}

output "public_ip" {
  value       = aws_eip.nextgen_ip.public_ip
  description = "IP publique de l'instance EC2"
}