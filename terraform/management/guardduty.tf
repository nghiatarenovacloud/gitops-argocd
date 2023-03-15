resource "aws_guardduty_organization_admin_account" "delegated_admin" {
  admin_account_id = var.audit_account_id
}
