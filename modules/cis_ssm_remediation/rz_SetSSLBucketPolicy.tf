resource "aws_ssm_document" "RZ-SetSSLBucketPolicy" {
  name            = "RZ-SetSSLBucketPolicy"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_SetSSLBucketPolicy.yaml")
}