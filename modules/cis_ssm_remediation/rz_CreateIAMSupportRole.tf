resource "aws_ssm_document" "RZ-CreateIAMSupportRole" {
  name            = "RZ-CreateIAMSupportRole"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_CreateIAMSupportRole.yaml")
}