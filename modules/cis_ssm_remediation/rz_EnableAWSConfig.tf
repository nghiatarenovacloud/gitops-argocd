resource "aws_ssm_document" "RZ-EnableAWSConfig" {
  name            = "RZ-EnableAWSConfig"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableAWSConfig.yaml")
}