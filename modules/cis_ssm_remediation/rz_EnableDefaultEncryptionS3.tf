resource "aws_ssm_document" "RZ-EnableDefaultEncryptionS3" {
  name            = "RZ-EnableDefaultEncryptionS3"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableDefaultEncryptionS3.yaml")
}