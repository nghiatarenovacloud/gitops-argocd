resource "aws_organizations_delegated_administrator" "sso" {
  account_id        = var.service_account_id
  service_principal = "sso.amazonaws.com"
}
