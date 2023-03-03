resource "aws_organizations_organization" "org" {
  aws_service_access_principals = var.organization_service

  feature_set          = "ALL"
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}


