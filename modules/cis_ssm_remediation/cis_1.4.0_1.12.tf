resource "aws_ssm_document" "cis_140_112" {
  name            = "RZ-CIS_1.4.0_1.12"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/cis_1.4.0_1.12.yaml")
}