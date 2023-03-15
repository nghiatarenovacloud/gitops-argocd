resource "aws_ssm_document" "RZ-CreateAccessLoggingBucket" {
  name            = "RZ-CreateAccessLoggingBucket"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_CreateAccessLoggingBucket.yaml")
}