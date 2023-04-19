resource "aws_ssm_document" "RZ-CreateCloudTrailMultiRegionTrail" {
  name            = "RZ-CreateCloudTrailMultiRegionTrail"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_CreateCloudTrailMultiRegionTrail.yaml")
}