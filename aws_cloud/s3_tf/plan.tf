variable "bucket_name" {
  description = "The name of the S3 bucket."
  default     = "mixua-s3-backup-bucket"
}

variable "user_name" {
  description = "The name of the IAM user."
  default     = "s3-backup-user"
}

provider "aws" {
  region = "eu-central-1"
}

resource "aws_s3_bucket" "s3_backup_bucket" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_backup_bucket_sse" {
  bucket = aws_s3_bucket.s3_backup_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_acl" "s3_backup_bucket_acl" {
  bucket = aws_s3_bucket.s3_backup_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_lifecycle_configuration" "s3_backup_bucket_lifecycle_configuration" {
  rule {
    id      = "${var.bucket_name}-rule"
    status  = "Enabled"

    transition {
      days          = 10
      storage_class = "GLACIER"
    }

    expiration {
      days = 30
    }
  }

  bucket = aws_s3_bucket.s3_backup_bucket.id
}

resource "aws_iam_user" "s3_backup_user" {
  name = var.user_name
}

resource "aws_iam_access_key" "s3_backup_user_access_key" {
  user = aws_iam_user.s3_backup_user.name
}

resource "aws_iam_user_policy" "s3_backup_user_policy" {
  name   = "${var.bucket_name}-user-policy"
  user   = aws_iam_user.s3_backup_user.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.s3_backup_bucket.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.s3_backup_bucket.arn}/*"
      }
    ]
  })
}

output "access_key" {
  value = aws_iam_access_key.s3_backup_user_access_key.id
}

output "secret_key" {
  value = aws_iam_access_key.s3_backup_user_access_key.secret
  sensitive = true
}
