# Apply below resources at Master account before moving with Audit account
## Enable SecurityHub service at Master account
resource "aws_securityhub_account" "this" {}

## Enable delegated admin to Audit account
resource "aws_securityhub_organization_admin_account" "delegated_admin" {
  admin_account_id = var.audit_account_id
  depends_on       = [aws_securityhub_account.this]
}
