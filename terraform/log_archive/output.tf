output "s3_bucket_arn_guardduty_findings" {
  value = aws_s3_bucket.guardduty_findings.arn
}

output "kms_key_arn_guardduty_findings" {
  value = aws_kms_key.guardduty_findings.arn
}
