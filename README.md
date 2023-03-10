# renozone

AWS Landing Zone with hardened CIS

# How to run code

1. First create organization by console
2. Go to **org.tf** file and comment code:

```
resource "aws_organizations_organization" "org" {
  # Comment the below line
  #aws_service_access_principals = var.organization_service
  #feature_set          = "ALL"
  #enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}
```

3. Run **import** command:

   `terraform import aws_organizations_organization.org <org.id>`

   And you will receive the following result:

   `terraform manage resource "aws_organizations_organization" success`

4. Delete **comment** code:

```
resource "aws_organizations_organization" "org" {
  # Delete comment code below:
  aws_service_access_principals = var.organization_service
  feature_set          = "ALL"
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}
```

5. Perform **plan** action:

   `terraform plan`

6. Perform **apply** action:

   `terraform apply --auto-approve`
