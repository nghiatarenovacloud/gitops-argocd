resource "aws_ssm_document" "RZ-EnableEbsEncryptionByDefault" {
  name            = "RZ-EnableEbsEncryptionByDefault"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableEbsEncryptionByDefault.yaml")
}