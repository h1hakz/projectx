# Vulnerable Terraform config for IaC (Trivy) demo
resource "aws_s3_bucket" "vulnerable" {
  bucket = "my-vulnerable-bucket"

  # Public access block disabled
  force_destroy = true
}

resource "aws_security_group" "open" {
  name        = "open-to-world"
  description = "Allows all traffic from anywhere"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_user" "admin" {
  name = "overprivileged-admin"
}

resource "aws_iam_user_policy_attachment" "admin_access" {
  user       = aws_iam_user.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
