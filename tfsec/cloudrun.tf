# vulnerable.tf

provider "aws" {
  region = "us-east-1"
}

# ❌ Public S3 bucket (insecure ACL + no encryption)
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-tfsec-test-bucket"
  acl    = "public-read"   # tfsec should flag this
}

# ❌ Security group wide open to the world
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow all inbound traffic"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # tfsec should flag this
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
