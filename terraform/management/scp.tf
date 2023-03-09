locals {
  scp_prefix = "renozone-default"
}

##################################################################
# [C][1] PreventLeaveOrg
##################################################################
data "aws_iam_policy_document" "prevent_leave_org" {
  statement {
    sid       = "PreventLeaveOrg"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }
}

resource "aws_organizations_policy" "prevent_leave_org" {
  name        = "${scp_prefix}-prevent-leave-org"
  description = "Prevent LeaveOrganization action"
  content     = data.aws_iam_policy_document.prevent_leave_org.json
}

##################################################################
# [C][2] RestrictRegions
##################################################################
data "aws_iam_policy_document" "restrict_regions" {
  statement {
    sid       = "RestrictRegions"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"

      values = [
        "us-east-1",
        "ap-southeast-1"
      ]
    }
  }
}

resource "aws_organizations_policy" "restrict_regions" {
  name        = "${scp_prefix}-restrict-regions"
  description = "Deny regions except us-east-1 and ap-southeast-1"
  content     = data.aws_iam_policy_document.restrict_regions.json
}

##################################################################
# [C][3] PreventPublicS3
##################################################################
data "aws_iam_policy_document" "prevent_public_s3" {
  statement {
    sid       = "PreventPublicS3"
    effect    = "Deny"
    actions   = ["s3:PutAccountPublicAccessBlock"]
    resources = ["*"]
  }
}

resource "aws_organizations_policy" "prevent_public_s3" {
  name        = "${scp_prefix}-prevent-public-s3"
  description = "Prevent Public S3 buckets"
  content     = data.aws_iam_policy_document.prevent_public_s3.json
}

##################################################################
# [C][4] PreventDisableEBSEncryption
##################################################################
data "aws_iam_policy_document" "prevent_disable_ebs_encryption" {
  statement {
    sid       = "PreventPublicS3"
    effect    = "Deny"
    actions   = ["ec2:DisableEbsEncryptionByDefault"]
    resources = ["*"]
  }
}

resource "aws_organizations_policy" "prevent_disable_ebs_encryption" {
  name        = "${scp_prefix}-prevent-disable-ebs-encryption"
  description = "Prevent EBS encryption to be disabled"
  content     = data.aws_iam_policy_document.prevent_disable_ebs_encryption.json
}

##################################################################
# [C][5] PreventModifyConfig
##################################################################
data "aws_iam_policy_document" "prevent_modify_config" {
  statement {
    sid    = "PreventModifyConfig"
    effect = "Deny"
    actions = [
      "config:DeleteConfigurationAggregator",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:DeleteRetentionConfiguration",
      "config:PutConfigurationAggregator",
      "config:PutConfigurationRecorder",
      "config:PutDeliveryChannel",
      "config:PutRetentionConfiguration",
      "config:StopConfigurationRecorder"
    ]
    resources = ["*"]
  }
}

resource "aws_organizations_policy" "prevent_modify_config" {
  name        = "${scp_prefix}-prevent-modify-config"
  description = "Prevent AWS Config modifications"
  content     = data.aws_iam_policy_document.prevent_modify_config.json
}

##################################################################
# [C][6] PreventModifyGuardDuty
##################################################################
data "aws_iam_policy_document" "prevent_modify_guardduty" {
  statement {
    sid    = "PreventModifyGuardDuty"
    effect = "Deny"
    actions = [
      "guardduty:DeclineInvitations",
      "guardduty:Disassociate*",
      "guardduty:DeleteDetector",
      "guardduty:DeleteInvitations",
      "guardduty:DeleteIPSet",
      "guardduty:DeleteMembers",
      "guardduty:DeleteThreatIntelSet",
      "guardduty:StopMonitoringMembers",
      "guardduty:UpdateDetector"
    ]
    resources = ["*"]
  }
}

resource "aws_organizations_policy" "prevent_modify_guardduty" {
  name        = "${scp_prefix}-prevent-modify-guardduty"
  description = "Prevent Amazon GuardDuty modifications"
  content     = data.aws_iam_policy_document.prevent_modify_guardduty.json
}

##################################################################
# [C][7] PreventShareResourceOutsite
##################################################################
data "aws_iam_policy_document" "prevent_share_resource_outsite" {
  statement {
    sid       = "PreventShareResourceOutsite"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "ram:AllowsExternalPrincipals"

      values = [
        "true"
      ]
    }
  }
}

resource "aws_organizations_policy" "prevent_share_resource_outsite" {
  name        = "${scp_prefix}-prevent-share-resource-outsite"
  description = "Prevent AWS resources to be shared outsite"
  content     = data.aws_iam_policy_document.prevent_share_resource_outsite.json
}

##################################################################
# [CIS][1.4&1.7] PreventRootActivity
##################################################################

data "aws_iam_policy_document" "prevent_root_activity" {
  statement {
    sid       = "PreventRootActivity"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"

      values = [
        "arn:aws:iam::*:root"
      ]
    }
  }
}

resource "aws_organizations_policy" "prevent_root_activity" {
  name        = "${scp_prefix}-prevent-root-activity"
  description = "Prevent Root Activity"
  content     = data.aws_iam_policy_document.prevent_root_activity.json
}

##################################################################
# [CIS][2.2.1] EnforceEBSEncryption
##################################################################
data "aws_iam_policy_document" "enforce_ebs_encryption" {
  statement {
    sid       = "EnforceEBSEncryption"
    effect    = "Deny"
    actions   = ["ec2:CreateVolume"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "ec2:Encrypted"

      values = [
        "true"
      ]
    }
  }
}

resource "aws_organizations_policy" "enforce_ebs_encryption" {
  name        = "${scp_prefix}-enforce-ebs-encryption"
  description = "Enforce EBS encryption"
  content     = data.aws_iam_policy_document.enforce_ebs_encryption.json
}

##################################################################
# [CIS][2.3.1] EnforceRDSEncryption
##################################################################
data "aws_iam_policy_document" "enforce_rds_encryption" {
  statement {
    sid       = "EnforceRDSEncryption"
    effect    = "Deny"
    actions   = ["rds:CreateDBInstance"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "rds:StorageEncrypted"

      values = [
        "true"
      ]
    }
  }
}

resource "aws_organizations_policy" "enforce_rds_encryption" {
  name        = "${scp_prefix}-enforce-rds-encryption"
  description = "Enforce RDS encryption"
  content     = data.aws_iam_policy_document.enforce_rds_encryption.json
}

##################################################################
# [CIS][2.4.1] EnforceEFSEncryption
##################################################################
data "aws_iam_policy_document" "enforce_efs_encryption" {
  statement {
    sid       = "EnforceEFSEncryption"
    effect    = "Deny"
    actions   = ["elasticfilesystem:CreateFileSystem"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "elasticfilesystem:Encrypted"

      values = [
        "true"
      ]
    }
  }
}

resource "aws_organizations_policy" "enforce_efs_encryption" {
  name        = "${scp_prefix}-enforce-efs-encryption"
  description = "Enforce EFS encryption"
  content     = data.aws_iam_policy_document.enforce_efs_encryption.json
}


