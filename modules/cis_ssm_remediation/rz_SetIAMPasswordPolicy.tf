resource "aws_ssm_document" "RZ-SetIAMPasswordPolicy" {
  name            = "RZ-SetIAMPasswordPolicy"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_SetIAMPasswordPolicy.yaml")
}