resource "aws_ssm_document" "RZ-RevokeUnrotatedKeys" {
  name            = "RZ-RevokeUnrotatedKeys"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_RevokeUnrotatedKeys.yaml")
}