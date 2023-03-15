locals {
  s3_prefix = "renozone-default-${data.aws_caller_identity.this.account_id}"
}

resource "aws_s3_bucket" "guardduty_findings" {
  bucket = "${s3_prefix}-guardduty-findings-export"

  tags = {
    Name = "${s3_prefix}-guardduty-findings-export"
  }
}

resource "aws_s3_bucket_acl" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.guardduty_findings.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_kms_key" "guardduty_findings" {
  description  = "KMS key for S3 bucket encryption of guardduty-findings-export"
  key_usage    = "ENCRYPT_DECRYPT"
  is_enabled   = true
  multi_region = false
  tags         = {}
}
