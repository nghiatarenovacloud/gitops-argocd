locals {
  selected_scp = ["PreventRootactivity"]
}
resource "aws_organizations_policy_attachment" "unit" {
  for_each  = toset(local.selected_scp)
  policy_id = var.scp_id[each.key]
  target_id = var.target_id
}
