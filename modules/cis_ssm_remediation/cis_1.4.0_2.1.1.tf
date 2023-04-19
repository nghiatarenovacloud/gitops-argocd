resource "aws_ssm_document" "cis_140_211" {
  name            = "RZ-CIS_1.4.0_2.1.1"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/cis_1.4.0_2.1.1.yaml")
}