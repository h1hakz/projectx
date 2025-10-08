# main.tf (Hardened Secure Version)

provider "aws" {
  region = "us-east-1"
}

######################################
# SECURE S3 BUCKET WITH KMS ENCRYPTION
######################################

# Create a custom KMS key for encryption
resource "aws_kms_key" "s3_kms" {
  description             = "KMS key for encrypting S3 data"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "S3EncryptionKey"
  }
}

# S3 Bucket
resource "aws_s3_bucket" "secure_data" {
  bucket = "my-secure-kms-encrypted-bucket-12345"

  tags = {
    Name        = "Encrypted Bucket"
    Environment = "Production"
  }
}

# Enable KMS-based encryption (SSE-KMS)
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms.arn
    }
  }
}

# Block all public access
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

  # Restrict inbound SSH to trusted range
  ingress {
    description = "SSH from corporate/VPN network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # Replace with your own CIDR
  }

  # Restrict outbound (egress) instead of allowing 0.0.0.0/0
  egress {
    description = "Allow outbound only to trusted network"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["203.0.113.0/24"] # Replace with your org/public network or NAT gateway CIDR
  }

  tags = {
    Name = "Restricted SSH Access"
  }
}
