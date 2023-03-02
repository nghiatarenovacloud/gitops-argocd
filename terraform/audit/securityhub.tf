locals {
  securityhub_members = {
    # "123456789012" = "workload-1@mycompany.com",
  }
}

# Only apply below resources after configured delegated admin at Master account
## Auto enable security hub in organization member accounts
resource "aws_securityhub_organization_configuration" "delegated_admin" {
  auto_enable = true
}

## Add members to be managed under Security Hub delegated admin
resource "aws_securityhub_member" "members" {
  for_each   = local.securityhub_members
  account_id = each.key
  email      = each.value
  depends_on = [aws_securityhub_organization_configuration.delegated_admin]
}
