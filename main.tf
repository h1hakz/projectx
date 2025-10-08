# main.tf (Secure Version)

provider "aws" {
  region = "us-east-1"
}

######################################
# SECURE S3 BUCKET WITH ENCRYPTION
######################################
resource "aws_s3_bucket" "secure_data" {
  bucket = "my-secure-encrypted-bucket-12345"

  tags = {
    Name        = "Encrypted Bucket"
    Environment = "Production"
  }
}

# Enable server-side encryption (AES256)
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all forms of public access
resource "aws_s3_bucket_public_access_block" "secure_block" {
  bucket                  = aws_s3_bucket.secure_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

######################################
# SECURE SECURITY GROUP (RESTRICTED SSH)
######################################
resource "aws_security_group" "ssh_restricted" {
  name        = "ssh-restricted"
  description = "Allows SSH only from trusted IPs"

  ingress {
    description = "SSH from corporate/VPN network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # Replace with your trusted IP range
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Restricted SSH Access"
  }
}
