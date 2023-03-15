resource "aws_ssm_document" "RZ-ConfigureS3BucketPublicAccessBlock" {
  name            = "RZ-ConfigureS3BucketPublicAccessBlock"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_ConfigureS3BucketPublicAccessBlock.yaml")
}