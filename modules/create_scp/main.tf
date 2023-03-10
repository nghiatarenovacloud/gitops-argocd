resource "aws_organizations_policy" "project" {
  for_each = var.scp
  name     = each.key
  content  = jsonencode(each.value)
  tags     = { Name = each.key }
}
