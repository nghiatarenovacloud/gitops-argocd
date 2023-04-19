resource "aws_ssm_document" "RZ-EnableCloudTrailToCloudWatchLogging" {
  name            = "RZ-EnableCloudTrailToCloudWatchLogging"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableCloudTrailToCloudWatchLogging.yaml")
}