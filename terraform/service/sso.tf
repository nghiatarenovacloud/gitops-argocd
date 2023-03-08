locals {
  group_prefix = "renozone-default"
}

data "aws_ssoadmin_instances" "default" {}

##################################################################
# Group AFT
##################################################################
resource "aws_identitystore_group" "aft" {
  display_name      = "${group_prefix}-aft"
  description       = "Default group for AFT"
  identity_store_id = tolist(data.aws_ssoadmin_instances.default.identity_store_ids)[0]
}

resource "aws_ssoadmin_permission_set" "aft" {
  name         = "${group_prefix}-aft-ps"
  instance_arn = tolist(data.aws_ssoadmin_instances.default.arns)[0]
}

resource "aws_ssoadmin_managed_policy_attachment" "aft" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.default.arns)[0]
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  permission_set_arn = aws_ssoadmin_permission_set.aft.arn
}

##################################################################
# Group Audit
##################################################################
resource "aws_identitystore_group" "audit" {
  display_name      = "${group_prefix}-audit"
  description       = "Default group for Audit"
  identity_store_id = tolist(data.aws_ssoadmin_instances.default.identity_store_ids)[0]
}

resource "aws_ssoadmin_permission_set" "audit" {
  name         = "${group_prefix}-audit-ps"
  instance_arn = tolist(data.aws_ssoadmin_instances.default.arns)[0]
}

resource "aws_ssoadmin_managed_policy_attachment" "audit" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.default.arns)[0]
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
  permission_set_arn = aws_ssoadmin_permission_set.audit.arn
}

##################################################################
# Group Security
##################################################################
resource "aws_identitystore_group" "security" {
  display_name      = "${group_prefix}-security"
  description       = "Default group for Security"
  identity_store_id = tolist(data.aws_ssoadmin_instances.default.identity_store_ids)[0]
}

resource "aws_ssoadmin_permission_set" "security" {
  name         = "${group_prefix}-security-ps"
  instance_arn = tolist(data.aws_ssoadmin_instances.default.arns)[0]
}

resource "aws_ssoadmin_managed_policy_attachment" "security" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.default.arns)[0]
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
  permission_set_arn = aws_ssoadmin_permission_set.security.arn
}

##################################################################
# Group Network
##################################################################
resource "aws_identitystore_group" "network" {
  display_name      = "${group_prefix}-network"
  description       = "Default group for Network"
  identity_store_id = tolist(data.aws_ssoadmin_instances.default.identity_store_ids)[0]
}

resource "aws_ssoadmin_permission_set" "network" {
  name         = "${group_prefix}-network-ps"
  instance_arn = tolist(data.aws_ssoadmin_instances.default.arns)[0]
}

resource "aws_ssoadmin_managed_policy_attachment" "network" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.default.arns)[0]
  managed_policy_arn = "arn:aws:iam::aws:policy/NetworkAdministrator"
  permission_set_arn = aws_ssoadmin_permission_set.network.arn
}
