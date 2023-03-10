# renozone

AWS Landing Zone with hardened CIS

# How to run code

1. First create organization by console
2. Go to org.tf file and comment code:

```
resource "aws_organizations_organization" "org" {
  #aws_service_access_principals = var.organization_service  => comment this line

  #feature_set          = "ALL"=> comment this line
  #enabled_policy_types = ["SERVICE_CONTROL_POLICY"]=> comment this line
}
```

3. Run import command : terraform import aws_organizations_organization.org <org.id>
   => terraform manage resource "aws_organizations_organization" success
4. Delete comment code:

```
resource "aws_organizations_organization" "org" {
  aws_service_access_principals = var.organization_service  => delete comment this line

  feature_set          = "ALL"=> delete comment this line
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]=> delete comment this line
}
```

5. Run terraform plan
6. Run terraform apply --auto-approve
