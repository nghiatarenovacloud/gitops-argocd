resource "aws_ssm_document" "cis_140_35" {
  name            = "RZ-CIS_1.4.0_3.5"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/cis_1.4.0_3.5.yaml")
}