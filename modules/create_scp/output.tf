output "scp_id" {
  value = zipmap([for item in aws_organizations_policy.project : item.tags_all["Name"]], [for item in aws_organizations_policy.project : item.id])
  # value = [for item in aws_organizations_policy.project : [item.tags_all["Name"]] : item.id }]
}
