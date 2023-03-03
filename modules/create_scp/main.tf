resource "aws_organizations_policy" "project" {
  for_each = var.scp
  name     = each.key
  #   content = <<CONTENT
  # {
  #   "Version": "2012-10-17",
  #   "Statement": {
  #     "Effect": "Allow",
  #     "Action": "*",
  #     "Resource": "*"
  #   }
  # }
  # CONTENT
  content = jsonencode(each.value)
  tags    = { Name = each.key }
}
