resource "aws_ssm_document" "RZ-RemoveVPCDefaultSecurityGroupRules" {
  name            = "RZ-RemoveVPCDefaultSecurityGroupRules"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_RemoveVPCDefaultSecurityGroupRules.yaml")
}