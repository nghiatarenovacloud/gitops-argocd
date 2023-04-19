resource "aws_ssm_document" "RZ-EnableCloudTrailEncryption" {
  name            = "RZ-EnableCloudTrailEncryption"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableCloudTrailEncryption.yaml")
}