# safe.tf

provider "aws" {
  region = "us-east-1"
}

# ✅ Secure S3 bucket with private ACL and encryption
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-tfsec-test-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# ✅ Block all public access at account level
resource "aws_s3_bucket_public_access_block" "secure_bucket_block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ✅ Security group restricted to specific subnet
resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Allow limited inbound traffic"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]  # restricted subnet, not 0.0.0.0/0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/24"]
  }
}
