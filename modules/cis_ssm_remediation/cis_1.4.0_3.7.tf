resource "aws_ssm_document" "cis_140_37" {
  name            = "RZ-CIS_1.4.0_3.7"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/cis_1.4.0_3.7.yaml")
}