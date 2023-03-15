resource "aws_ssm_document" "RZ-RevokeUnusedIAMUserCredentials" {
  name            = "RZ-RevokeUnusedIAMUserCredentials"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_RevokeUnusedIAMUserCredentials.yaml")
}