resource "aws_ssm_document" "RZ-CreateLogMetricFilterAndAlarm" {
  name            = "RZ-CreateLogMetricFilterAndAlarm"
  document_format = "YAML"
  document_type   = "Automation"
  content = file("${path.module}/ssm_contents/rz_CreateLogMetricFilterAndAlarm.yaml")
}