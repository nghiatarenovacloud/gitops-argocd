resource "aws_organizations_policy_attachment" "unit" {
  policy_id = var.scp_id
  target_id = var.target_id
}