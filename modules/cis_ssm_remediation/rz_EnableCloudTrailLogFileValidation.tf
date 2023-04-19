resource "aws_ssm_document" "RZ-EnableCloudTrailLogFileValidation" {
  name            = "RZ-EnableCloudTrailLogFileValidation"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableCloudTrailLogFileValidation.yaml")
}