provider "aws" {
  region = "us-east-1"
}

# ISSUE 1: S3 bucket without server-side encryption enabled.
# Trivy should flag this as a medium/high severity issue (e.g., AVD-AWS-0088).
resource "aws_s3_bucket" "unencrypted_data" {
  bucket = "my-super-secret-unencrypted-bucket-12345"

  tags = {
    Name        = "Unencrypted Bucket"
    Environment = "Test"
  }
}

# ISSUE 2: Security group allowing unrestricted inbound traffic on SSH port 22.
# Trivy should flag this as a critical severity issue (e.g., AVD-AWS-0107).
resource "aws_security_group" "ssh_wide_open" {
  name        = "ssh-wide-open"
  description = "Allows SSH access from any IP address"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # This is the vulnerability.
  }

  tags = {
    Name = "Public SSH Access"
  }
}
