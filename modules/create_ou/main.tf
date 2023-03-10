resource "aws_organizations_organizational_unit" "ou" {
  name      = var.name
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

