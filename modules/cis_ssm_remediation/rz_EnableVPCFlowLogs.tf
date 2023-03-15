resource "aws_ssm_document" "RZ-EnableVPCFlowLogs" {
  name            = "RZ-EnableVPCFlowLogs"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_EnableVPCFlowLogs.yaml")
}