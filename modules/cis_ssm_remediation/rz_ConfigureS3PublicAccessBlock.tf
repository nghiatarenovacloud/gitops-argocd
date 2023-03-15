resource "aws_ssm_document" "RZ-ConfigureS3PublicAccessBlock" {
  name            = "RZ-ConfigureS3PublicAccessBlock"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_ConfigureS3PublicAccessBlock.yaml")
}