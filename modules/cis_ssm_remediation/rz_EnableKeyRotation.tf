resource "aws_ssm_document" "RZ-EnableKeyRotation" {
  name            = "RZ-EnableKeyRotation"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableKeyRotation.yaml")
}