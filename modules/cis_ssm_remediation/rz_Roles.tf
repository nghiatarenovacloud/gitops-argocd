data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

variable "sec_hub_admin_account" {
  description = "Admin account number"
  type        = string
}
##RZ-SetIAMPasswordPolicy
resource "aws_iam_policy" "remediation_policy_set_iam_password_policy" {
  policy = {
    Statement = [
      {
        Action = [
          "iam:UpdateAccountPasswordPolicy",
          "iam:GetAccountPasswordPolicy",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZRemediationPolicySetIAMPasswordPolicy"
}

resource "aws_iam_policy" "remediation_role_set_iam_password_policy" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action   = "iam:PassRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SetIAMPasswordPolicy"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-SetIAMPasswordPolicy"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"])
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SetIAMPasswordPolicy"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZRemediationRoleSetIAMPasswordPolicy"
}

resource "aws_iam_role" "remediation_role_set_iam_password_policy" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-SetIAMPasswordPolicy"
}

resource "aws_iam_role_policy_attachment" "remediation_policy_set_iam_password_policy-attach" {
  role       = aws_iam_role.remediation_role_set_iam_password_policy.name
  policy_arn = aws_iam_policy.remediation_policy_set_iam_password_policy.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_set_iam_password_policy-attach" {
  role       = aws_iam_role.remediation_role_set_iam_password_policy.name
  policy_arn = aws_iam_policy.remediation_role_set_iam_password_policy.arn
}


##RZ-RevokeUnusedIAMUserCredentials
resource "aws_iam_policy" "remediation_policy_revoke_unused_iam_user_credentials" {
  policy = {
    Statement = [
      {
        Action = [
          "iam:UpdateAccessKey",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:GetUser",
          "iam:GetLoginProfile",
          "iam:DeleteLoginProfile"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":user/*"])
      },
      {
        Action = "config:ListDiscoveredResources"
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZRemediationPolicyRevokeUnusedIAMUserCredentials"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_revoke_unused_iam_user_credentials_member_account_role5_c008_b43.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_revoke_unused_iam_user_credentials" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RevokeUnusedIAMUserCredentials"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-RevokeUnusedIAMUserCredentials"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RevokeUnusedIAMUserCredentials"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleRevokeUnusedIAMUserCredentialsSHARRMemberBasePolicy6519E750"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_revoke_unused_iam_user_credentials_member_account_role5_c008_b43.arn
  // ]
}

resource "aws_iam_role" "remediation_role_revoke_unused_iam_user_credentials_member_account_role5_c008_b43" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "SO0111-RevokeUnusedIAMUserCredentials"
}

##RZ-RevokeUnrotatedKeys
resource "aws_iam_policy" "sharr_remediation_policy_revoke_unrotated_keys7_f92_eced" {
  policy = {
    Statement = [
      {
        Action = [
          "iam:UpdateAccessKey",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:GetUser"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":user/*"])
      },
      {
        Action = "config:ListDiscoveredResources"
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyRevokeUnrotatedKeys7F92ECED"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_revoke_unrotated_keys_member_account_role_bc193_a84.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_revoke_unrotated_keys_sharr_member_base_policy493293_ca" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RevokeUnrotatedKeys"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-RevokeUnrotatedKeys"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RevokeUnrotatedKeys"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleRevokeUnrotatedKeysSHARRMemberBasePolicy493293CA"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_revoke_unrotated_keys_member_account_role_bc193_a84.arn
  // ]
}

resource "aws_iam_role" "remediation_role_revoke_unrotated_keys_member_account_role_bc193_a84" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "SO0111-RevokeUnrotatedKeys"
}

##RZ-CreateIAMSupportRole
resource "aws_iam_policy" "sharr_remediation_policy_create_iam_support_role_b5_ddf732" {
  policy = {
    Statement = [
      {
        Action = [
          "iam:GetRole",
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:TagRole"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/aws_incident_support_role"])
      },
      {
        Action = "iam:AttachRolePolicy"
        Effect = "Deny"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateIAMSupportRole"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyCreateIAMSupportRoleB5DDF732"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_create_iam_support_role_member_account_role_fd80_f5_f3.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_create_iam_support_role_sharr_member_base_policy_b811_ff40" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateIAMSupportRole"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-CreateIAMSupportRole"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateIAMSupportRole"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleCreateIAMSupportRoleSHARRMemberBasePolicyB811FF40"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_create_iam_support_role_member_account_role_fd80_f5_f3.arn
  // ]
}

resource "aws_iam_role" "remediation_role_create_iam_support_role_member_account_role_fd80_f5_f3" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-CreateIAMSupportRole"
}

##RZ-EnableDefaultEncryptionS3
resource "aws_iam_policy" "sharr_remediation_policy_enable_default_encryption_s37717_fb1_c" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutEncryptionConfiguration",
          "kms:GenerateDataKey"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableDefaultEncryptionS37717FB1C"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_default_encryption_s3_member_account_role_d9_d87_c04.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_enable_default_encryption_s3_sharr_member_base_policy_b6_b36_b9_a" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableDefaultEncryptionS3"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableDefaultEncryptionS3"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableDefaultEncryptionS3"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableDefaultEncryptionS3SHARRMemberBasePolicyB6B36B9A"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_default_encryption_s3_member_account_role_d9_d87_c04.arn
  // ]
}

resource "aws_iam_role" "remediation_role_enable_default_encryption_s3_member_account_role_d9_d87_c04" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-EnableDefaultEncryptionS3"
}

##RZ-SetSSLBucketPolicy
resource "aws_iam_policy" "sharr_remediation_policy_set_ssl_bucket_policy2_b2017_fe" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicySetSSLBucketPolicy2B2017FE"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_set_ssl_bucket_policy_member_account_role_d6_bb5274.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_set_ssl_bucket_policy_sharr_member_base_policy21_ebf952" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SetSSLBucketPolicy"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-SetSSLBucketPolicy"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SetSSLBucketPolicy"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleSetSSLBucketPolicySHARRMemberBasePolicy21EBF952"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_set_ssl_bucket_policy_member_account_role_d6_bb5274.arn
  // ]
}

resource "aws_iam_role" "remediation_role_set_ssl_bucket_policy_member_account_role_d6_bb5274" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-SetSSLBucketPolicy"
}

##RZ-ConfigureS3PublicAccessBlock
resource "aws_iam_policy" "sharr_remediation_policy_configure_s3_public_access_block_ead9_ca55" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutAccountPublicAccessBlock",
          "s3:GetAccountPublicAccessBlock"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyConfigureS3PublicAccessBlockEAD9CA55"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_public_access_block_member_account_role98_a4_bc1_d.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_configure_s3_public_access_block_sharr_member_base_policy26_bf29_a6" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3PublicAccessBlock"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-ConfigureS3PublicAccessBlock"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3PublicAccessBlock"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleConfigureS3PublicAccessBlockSHARRMemberBasePolicy26BF29A6"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_public_access_block_member_account_role98_a4_bc1_d.arn
  // ]
}

resource "aws_iam_role" "remediation_role_configure_s3_public_access_block_member_account_role98_a4_bc1_d" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-ConfigureS3PublicAccessBlock"
}

##RZ-ConfigureS3BucketPublicAccessBlock
resource "aws_iam_policy" "sharr_remediation_policy_configure_s3_bucket_public_access_block2_e4_ef13_d" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyConfigureS3BucketPublicAccessBlock2E4EF13D"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_bucket_public_access_block_member_account_role_c78_f6_ee7.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_configure_s3_bucket_public_access_block_sharr_member_base_policy_b9_dcbd99" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3BucketPublicAccessBlock"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-ConfigureS3BucketPublicAccessBlock"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3BucketPublicAccessBlock"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleConfigureS3BucketPublicAccessBlockSHARRMemberBasePolicyB9DCBD99"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_bucket_public_access_block_member_account_role_c78_f6_ee7.arn
  // ]
}

resource "aws_iam_role" "remediation_role_configure_s3_bucket_public_access_block_member_account_role_c78_f6_ee7" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-ConfigureS3BucketPublicAccessBlock"
}

##RZ-EnableEbsEncryptionByDefault
resource "aws_iam_policy" "sharr_remediation_policy_enable_ebs_encryption_by_default_ed8_bc775" {
  policy = {
    Statement = [
      {
        Action = [
          "ec2:EnableEBSEncryptionByDefault",
          "ec2:GetEbsEncryptionByDefault"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableEbsEncryptionByDefaultED8BC775"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_ebs_encryption_by_default_member_account_role_df17_ff59.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_enable_ebs_encryption_by_default_sharr_member_base_policy77_cf4834" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableEbsEncryptionByDefault"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableEbsEncryptionByDefault"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableEbsEncryptionByDefault"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableEbsEncryptionByDefaultSHARRMemberBasePolicy77CF4834"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_ebs_encryption_by_default_member_account_role_df17_ff59.arn
  // ]
}

resource "aws_iam_role" "remediation_role_enable_ebs_encryption_by_default_member_account_role_df17_ff59" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-EnableEbsEncryptionByDefault"
}

##RZ-CreateCloudTrailMultiRegionTrail
resource "aws_iam_policy" "sharr_remediation_policy_create_cloud_trail_multi_region_trail59_b12044" {
  policy = {
    Statement = [
      {
        Action = [
          "cloudtrail:CreateTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:StartLogging"
        ]
        Effect = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "s3:CreateBucket",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketLogging",
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":s3:::RZ-*"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyCreateCloudTrailMultiRegionTrail59B12044"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_create_cloud_trail_multi_region_trail_member_account_role_f70577_ff.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_create_cloud_trail_multi_region_trail_sharr_member_base_policy_a86222_af" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateCloudTrailMultiRegionTrail"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-CreateCloudTrailMultiRegionTrail"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateCloudTrailMultiRegionTrail"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleCreateCloudTrailMultiRegionTrailSHARRMemberBasePolicyA86222AF"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_create_cloud_trail_multi_region_trail_member_account_role_f70577_ff.arn
  // ]
}

resource "aws_iam_role" "remediation_role_create_cloud_trail_multi_region_trail_member_account_role_f70577_ff" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-CreateCloudTrailMultiRegionTrail"
}

##RZ-EnableCloudTrailLogFileValidation
resource "aws_iam_policy" "sharr_remediation_policy_enable_cloud_trail_log_file_validation00359_a88" {
  policy = {
    Statement = [
      {
        Action = [
          "cloudtrail:UpdateTrail",
          "cloudtrail:GetTrail"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":cloudtrail:*:", data.aws_caller_identity.current.account_id, ":trail/*"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableCloudTrailLogFileValidation00359A88"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_cloud_trail_log_file_validation_member_account_role3_f5_f7157.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_enable_cloud_trail_log_file_validation_sharr_member_base_policy85_a07_c2_d" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailLogFileValidation"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableCloudTrailLogFileValidation"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailLogFileValidation"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableCloudTrailLogFileValidationSHARRMemberBasePolicy85A07C2D"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_cloud_trail_log_file_validation_member_account_role3_f5_f7157.arn
  // ]
}

resource "aws_iam_role" "remediation_role_enable_cloud_trail_log_file_validation_member_account_role3_f5_f7157" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-EnableCloudTrailLogFileValidation"
}

##RZ-EnableCloudTrailToCloudWatchLogging
resource "aws_iam_policy" "sharr_remediation_policy_enable_cloud_trail_to_cloud_watch_logging_a9_bbb945" {
  policy = {
    Statement = [
      {
        Action = "cloudtrail:UpdateTrail"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":cloudtrail:*:", data.aws_caller_identity.current.account_id, ":trail/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = aws_iam_role.ctcwremediationrole7_ab69_d0_b.arn
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:DescribeLogGroups"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableCloudTrailToCloudWatchLoggingA9BBB945"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_cloud_trail_to_cloud_watch_logging_member_account_role_e7_e9_c206.arn
  // ]
}

resource "aws_iam_role" "ctcwremediationrole7_ab69_d0_b" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = join("", ["cloudtrail.", data.aws_partition.current.dns_suffix])
        }
      }
    ]
    Version = "2012-10-17"
  }
  force_detach_policies = [
    {
      PolicyDocument = {
        Statement = [
          {
            Action = "logs:CreateLogStream"
            Effect = "Allow"
            Resource = join("", ["arn:", data.aws_partition.current.partition, ":logs:*:*:log-group:*"])
          },
          {
            Action = "logs:PutLogEvents"
            Effect = "Allow"
            Resource = join("", ["arn:", data.aws_partition.current.partition, ":logs:*:*:log-group:*:log-stream:*"])
          }
        ]
        Version = "2012-10-17"
      }
      PolicyName = "default_lambdaPolicy"
    }
  ]
  name = "RZ-CloudTrailToCloudWatchLogs"
}

##RZ-EnableAWSConfig
resource "aws_iam_policy" "sharr_remediation_policy_enable_aws_config8_a0259_d3" {
  policy = {
    Statement = [
      {
        Action = [
          "iam:GetRole",
          "iam:PassRole"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"]),
          join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateAccessLoggingBucket"])
        ]
      },
      {
        Action = [
          "sns:CreateTopic",
          "sns:SetTopicAttributes"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":sns:*:", data.aws_caller_identity.current.account_id, ":RZ-SHARR-AWSConfigNotification"])
      },
      {
        Action = "ssm:StartAutomationExecution"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/ASR-CreateAccessLoggingBucket:*"])
      },
      {
        Action = [
          "ssm:GetAutomationExecution",
          "config:PutConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:DescribeConfigurationRecorders",
          "config:StartConfigurationRecorder"
        ]
        Effect = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "s3:CreateBucket",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketLogging",
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":s3:::RZ-*"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableAWSConfig8A0259D3"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_aws_config_member_account_role3914_b25_f.arn
  // ]
}

##RZ-ConfigureS3BucketLogging
resource "aws_iam_policy" "sharr_remediation_policy_configure_s3_bucket_logging9_f85_eee2" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutBucketLogging",
          "s3:CreateBucket",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketAcl"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyConfigureS3BucketLogging9F85EEE2"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_bucket_logging_member_account_role_e068390_d.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_configure_s3_bucket_logging_sharr_member_base_policy_ac4_f82_a8" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3BucketLogging"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-ConfigureS3BucketLogging"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3BucketLogging"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleConfigureS3BucketLoggingSHARRMemberBasePolicyAC4F82A8"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_bucket_logging_member_account_role_e068390_d.arn
  // ]
}

resource "aws_iam_role" "remediation_role_configure_s3_bucket_logging_member_account_role_e068390_d" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-ConfigureS3BucketLogging"
}

##RZ-EnableCloudTrailEncryption
resource "aws_iam_policy" "sharr_remediation_policy_enable_cloud_trail_encryption5715_da83" {
  policy = {
    Statement = [
      {
        Action = "cloudtrail:UpdateTrail"
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableCloudTrailEncryption5715DA83"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_cloud_trail_encryption_member_account_role_a936699_b.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_enable_cloud_trail_encryption_sharr_member_base_policy6489774_e" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailEncryption"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableCloudTrailEncryption"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailEncryption"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableCloudTrailEncryptionSHARRMemberBasePolicy6489774E"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_cloud_trail_encryption_member_account_role_a936699_b.arn
  // ]
}

resource "aws_iam_role" "remediation_role_enable_cloud_trail_encryption_member_account_role_a936699_b" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-EnableCloudTrailEncryption"
}

##RZ-EnableKeyRotation
resource "aws_iam_policy" "sharr_remediation_policy_enable_key_rotation7_dbfdfe8" {
  policy = {
    Statement = [
      {
        Action = [
          "kms:EnableKeyRotation",
          "kms:GetKeyRotationStatus"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableKeyRotation7DBFDFE8"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_key_rotation_member_account_role2366_f17_f.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_enable_key_rotation_sharr_member_base_policy_a6_e832_d4" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableKeyRotation"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableKeyRotation"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableKeyRotation"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableKeyRotationSHARRMemberBasePolicyA6E832D4"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_key_rotation_member_account_role2366_f17_f.arn
  // ]
}

resource "aws_iam_role" "remediation_role_enable_key_rotation_member_account_role2366_f17_f" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-EnableKeyRotation"
}

##RZ-EnableVPCFlowLogs
resource "aws_iam_policy" "sharr_remediation_policy_enable_vpc_flow_logs22_f36069" {
  policy = {
    Statement = [
      {
        Action = "ec2:CreateFlowLogs"
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ec2:*:", data.aws_caller_identity.current.account_id, ":vpc/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ec2:*:", data.aws_caller_identity.current.account_id, ":vpc-flow-log/*"])
        ]
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableVPCFlowLogs-remediationRole"])
      },
      {
        Action = "ssm:GetParameter"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RZ/CMK_REMEDIATION_ARN"])
      },
      {
        Action = [
          "ec2:DescribeFlowLogs",
          "logs:CreateLogGroup",
          "logs:DescribeLogGroups"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyEnableVPCFlowLogs22F36069"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_enable_vpc_flow_logs_member_account_role_b79_f3729.arn
  // ]
}

resource "aws_iam_role" "enable_vpc_flow_logsremediationrole00848_cdf" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
    Version = "2012-10-17"
  }
  force_detach_policies = [
    {
      PolicyDocument = {
        Statement = [
          {
            Action = [
              "logs:CreateLogGroup",
              "logs:CreateLogStream",
              "logs:DescribeLogGroups",
              "logs:DescribeLogStreams",
              "logs:PutLogEvents"
            ]
            Effect = "Allow"
            Resource = "*"
          }
        ]
        Version = "2012-10-17"
      }
      PolicyName = "default_lambdaPolicy"
    }
  ]
  name = "RZ-EnableVPCFlowLogs-remediationRole"
}

##RZ-CreateLogMetricFilterAndAlarm
resource "aws_iam_policy" "sharr_remediation_policy_create_log_metric_filter_and_alarm102_ac980" {
  policy = {
    Statement = [
      {
        Action = [
          "logs:PutMetricFilter",
          "cloudwatch:PutMetricAlarm"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":logs:*:", data.aws_caller_identity.current.account_id, ":log-group:*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":cloudwatch:*:", data.aws_caller_identity.current.account_id, ":alarm:*"])
        ]
      },
      {
        Action = [
          "sns:CreateTopic",
          "sns:SetTopicAttributes"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":sns:*:", data.aws_caller_identity.current.account_id, ":RZ-SHARR-LocalAlarmNotification"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "SHARRRemediationPolicyCreateLogMetricFilterAndAlarm102AC980"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_create_log_metric_filter_and_alarm_member_account_role_aa3_e3_c8_a.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_create_log_metric_filter_and_alarm_sharr_member_base_policy2_afeef94" {
  policy = {
    Statement = [
      {
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action = "iam:PassRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateLogMetricFilterAndAlarm"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-CreateLogMetricFilterAndAlarm"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateLogMetricFilterAndAlarm"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleCreateLogMetricFilterAndAlarmSHARRMemberBasePolicy2AFEEF94"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_create_log_metric_filter_and_alarm_member_account_role_aa3_e3_c8_a.arn
  // ]
}

resource "aws_iam_role" "remediation_role_create_log_metric_filter_and_alarm_member_account_role_aa3_e3_c8_a" {
  assume_role_policy = {
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SecurityHub-Member"])
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":root"])
        }
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZ-CreateLogMetricFilterAndAlarm"
}

##