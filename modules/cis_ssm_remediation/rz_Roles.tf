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
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":user/*"])
      },
      {
        Action   = "config:ListDiscoveredResources"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZRemediationPolicyRevokeUnusedIAMUserCredentials"
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
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RenoZone/*"])
      },
      {
        Action   = "iam:PassRole"
        Effect   = "Allow"
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RevokeUnusedIAMUserCredentials"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RZRemediationRoleRevokeUnusedIAMUserCredentials"
}

resource "aws_iam_role" "remediation_role_revoke_unused_iam_user_credentials" {
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
  name = "RZ-RevokeUnusedIAMUserCredentials"
}


resource "aws_iam_role_policy_attachment" "remediation_policy_revoke_unused_iam_user_credentials-attach" {
  role       = aws_iam_role.remediation_role_revoke_unused_iam_user_credentials.name
  policy_arn = aws_iam_policy.remediation_policy_revoke_unused_iam_user_credentials.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_revoke_unused_iam_user_credentials-attach" {
  role       = aws_iam_role.remediation_role_revoke_unused_iam_user_credentials.name
  policy_arn = aws_iam_policy.remediation_role_revoke_unused_iam_user_credentials.arn
}

##RZ-RevokeUnrotatedKeys
resource "aws_iam_policy" "remediation_policy_revoke_unrotated_keys" {
  policy = {
    Statement = [
      {
        Action = [
          "iam:UpdateAccessKey",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:GetUser"
        ]
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":user/*"])
      },
      {
        Action   = "config:ListDiscoveredResources"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyRevokeUnrotatedKeys"
}

resource "aws_iam_policy" "remediation_role_revoke_unrotated_keys" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RevokeUnrotatedKeys"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleRevokeUnrotatedKeys"
}

resource "aws_iam_role" "remediation_role_revoke_unrotated_keys" {
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
  name = "RZ-RevokeUnrotatedKeys"
}

resource "aws_iam_role_policy_attachment" "remediation_policy_revoke_unrotated_keys-attach" {
  role       = aws_iam_role.remediation_role_revoke_unrotated_keys.name
  policy_arn = aws_iam_policy.remediation_policy_revoke_unrotated_keys.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_revoke_unrotated_keys-attach" {
  role       = aws_iam_role.remediation_role_revoke_unrotated_keys.name
  policy_arn = aws_iam_policy.remediation_role_revoke_unrotated_keys.arn
}

##RZ-CreateIAMSupportRole
resource "aws_iam_policy" "remediation_policy_create_iam_support_role" {
  policy = {
    Statement = [
      {
        Action = [
          "iam:GetRole",
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:TagRole"
        ]
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/aws_incident_support_role"])
      },
      {
        Action   = "iam:AttachRolePolicy"
        Effect   = "Deny"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateIAMSupportRole"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyCreateIAMSupportRole"
}

resource "aws_iam_policy" "remediation_role_create_iam_support_role" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateIAMSupportRole"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleCreateIAMSupportRoleB811FF40"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_create_iam_support_role_member_account_role_fd80_f5_f3.arn
  // ]
}

resource "aws_iam_role" "remediation_role_create_iam_support_role_member_account_role" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_create_iam_support_role-attach" {
  role       = aws_iam_role.remediation_role_create_iam_support_role.name
  policy_arn = aws_iam_policy.remediation_policy_create_iam_support_role.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_create_iam_support_role-attach" {
  role       = aws_iam_role.remediation_role_create_iam_support_role.name
  policy_arn = aws_iam_policy.remediation_role_create_iam_support_role.arn
}

##RZ-EnableDefaultEncryptionS3
resource "aws_iam_policy" "remediation_policy_enable_default_encryption_s3" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutEncryptionConfiguration",
          "kms:GenerateDataKey"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableDefaultEncryptionS3"
}

resource "aws_iam_policy" "remediation_role_enable_default_encryption_s3" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableDefaultEncryptionS3"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableDefaultEncryptionS3"

}

resource "aws_iam_role" "remediation_role_enable_default_encryption_s3" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_default_encryption_s3-attach" {
  role       = aws_iam_role.remediation_role_enable_default_encryption_s3.name
  policy_arn = aws_iam_policy.remediation_policy_enable_default_encryption_s3.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_default_encryption_s3-attach" {
  role       = aws_iam_role.remediation_role_enable_default_encryption_s3.name
  policy_arn = aws_iam_policy.remediation_role_enable_default_encryption_s3.arn
}

##RZ-SetSSLBucketPolicy
resource "aws_iam_policy" "remediation_policy_set_ssl_bucket_policy" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicySetSSLBucketPolicy"
}

resource "aws_iam_policy" "remediation_role_set_ssl_bucket_policy" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-SetSSLBucketPolicy"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleSetSSLBucketPolicy"
}

resource "aws_iam_role" "remediation_role_set_ssl_bucket_policy" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_set_ssl_bucket_policy-attach" {
  role       = aws_iam_role.remediation_role_set_ssl_bucket_policy.name
  policy_arn = aws_iam_policy.remediation_policy_set_ssl_bucket_policy.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_set_ssl_bucket_policy-attach" {
  role       = aws_iam_role.remediation_role_set_ssl_bucket_policy.name
  policy_arn = aws_iam_policy.remediation_role_set_ssl_bucket_policy.arn
}

##RZ-ConfigureS3PublicAccessBlock
resource "aws_iam_policy" "remediation_policy_configure_s3_public_access_block" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutAccountPublicAccessBlock",
          "s3:GetAccountPublicAccessBlock"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyConfigureS3PublicAccessBlockEAD9CA55"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_public_access_block_member_account_role98_a4_bc1_d.arn
  // ]
}

resource "aws_iam_policy" "remediation_role_configure_s3_public_access_block" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3PublicAccessBlock"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleConfigureS3PublicAccessBlock26BF29A6"
  // CF Property(Roles) = [
  //   aws_iam_role.remediation_role_configure_s3_public_access_block_member_account_role98_a4_bc1_d.arn
  // ]
}

resource "aws_iam_role" "remediation_role_configure_s3_public_access_block" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_configure_s3_public_access_block-attach" {
  role       = aws_iam_role.remediation_role_configure_s3_public_access_block.name
  policy_arn = aws_iam_policy.remediation_policy_configure_s3_public_access_block.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_configure_s3_public_access_block-attach" {
  role       = aws_iam_role.remediation_role_configure_s3_public_access_block.name
  policy_arn = aws_iam_policy.remediation_role_configure_s3_public_access_block.arn
}

##RZ-ConfigureS3BucketPublicAccessBlock
resource "aws_iam_policy" "remediation_policy_configure_s3_bucket_public_access_block" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyConfigureS3BucketPublicAccessBlock"
}

resource "aws_iam_policy" "remediation_role_configure_s3_bucket_public_access_block" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3BucketPublicAccessBlock"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleConfigureS3BucketPublicAccessBlock"
}

resource "aws_iam_role" "remediation_role_configure_s3_bucket_public_access_block" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_configure_s3_bucket_public_access_block-attach" {
  role       = aws_iam_role.remediation_role_configure_s3_bucket_public_access_block.name
  policy_arn = aws_iam_policy.remediation_policy_configure_s3_bucket_public_access_block.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_configure_s3_public_access_block-attach" {
  role       = aws_iam_role.remediation_role_configure_s3_bucket_public_access_block.name
  policy_arn = aws_iam_policy.remediation_role_configure_s3_bucket_public_access_block.arn
}

##RZ-EnableEbsEncryptionByDefault
resource "aws_iam_policy" "remediation_policy_enable_ebs_encryption_by_default" {
  policy = {
    Statement = [
      {
        Action = [
          "ec2:EnableEBSEncryptionByDefault",
          "ec2:GetEbsEncryptionByDefault"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableEbsEncryptionByDefault"
}

resource "aws_iam_policy" "remediation_role_enable_ebs_encryption_by_default" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableEbsEncryptionByDefault"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableEbsEncryptionByDefault"
}

resource "aws_iam_role" "remediation_role_enable_ebs_encryption_by_default" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_ebs_encryption_by_default-attach" {
  role       = aws_iam_role.remediation_role_enable_ebs_encryption_by_default.name
  policy_arn = aws_iam_policy.remediation_policy_enable_ebs_encryption_by_default.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_ebs_encryption_by_default-attach" {
  role       = aws_iam_role.remediation_role_enable_ebs_encryption_by_default.name
  policy_arn = aws_iam_policy.remediation_role_enable_ebs_encryption_by_default.arn
}

##RZ-CreateCloudTrailMultiRegionTrail
resource "aws_iam_policy" "remediation_policy_create_cloud_trail_multi_region_trail" {
  policy = {
    Statement = [
      {
        Action = [
          "cloudtrail:CreateTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:StartLogging"
        ]
        Effect   = "Allow"
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
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":s3:::RZ-*"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyCreateCloudTrailMultiRegionTrail"
}

resource "aws_iam_policy" "remediation_role_create_cloud_trail_multi_region_trail" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateCloudTrailMultiRegionTrail"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleCreateCloudTrailMultiRegionTrail"
}

resource "aws_iam_role" "remediation_role_create_cloud_trail_multi_region_trail" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_create_cloud_trail_multi_region_trail-attach" {
  role       = aws_iam_role.remediation_role_enable_ebs_encryption_by_default.name
  policy_arn = aws_iam_policy.remediation_policy_create_cloud_trail_multi_region_trail.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_create_cloud_trail_multi_region_trail-attach" {
  role       = aws_iam_role.remediation_role_create_cloud_trail_multi_region_trail.name
  policy_arn = aws_iam_policy.remediation_role_create_cloud_trail_multi_region_trail.arn
}

##RZ-EnableCloudTrailLogFileValidation
resource "aws_iam_policy" "remediation_policy_enable_cloud_trail_log_file_validation" {
  policy = {
    Statement = [
      {
        Action = [
          "cloudtrail:UpdateTrail",
          "cloudtrail:GetTrail"
        ]
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":cloudtrail:*:", data.aws_caller_identity.current.account_id, ":trail/*"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableCloudTrailLogFileValidation"
}

resource "aws_iam_policy" "remediation_role_enable_cloud_trail_log_file_validation" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailLogFileValidation"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableCloudTrailLogFileValidation"
}

resource "aws_iam_role" "remediation_role_enable_cloud_trail_log_file_validation" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_cloud_trail_log_file_validation-attach" {
  role       = aws_iam_role.remediation_role_enable_cloud_trail_log_file_validation.name
  policy_arn = aws_iam_policy.remediation_policy_enable_cloud_trail_log_file_validation.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_cloud_trail_log_file_validation-attach" {
  role       = aws_iam_role.remediation_role_enable_cloud_trail_log_file_validation.name
  policy_arn = aws_iam_policy.remediation_role_enable_cloud_trail_log_file_validation.arn
}

##RZ-EnableCloudTrailToCloudWatchLogging
resource "aws_iam_policy" "remediation_policy_enable_cloud_trail_to_cloud_watch_logging" {
  policy = {
    Statement = [
      {
        Action   = "cloudtrail:UpdateTrail"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":cloudtrail:*:", data.aws_caller_identity.current.account_id, ":trail/*"])
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:DescribeLogGroups"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableCloudTrailToCloudWatchLogging"
}

resource "aws_iam_policy" "remediation_role_enable_cloud_trail_to_cloud_watch_logging" {
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
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailToCloudWatchLogging"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableCloudTrailToCloudWatchLogging"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"])
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailToCloudWatchLogging"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableCloudTrailToCloudWatchLogging"
}

resource "aws_iam_role" "remediation_role_enable_cloud_trail_to_cloud_watch_logging" {
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
  name = "RZ-EnableCloudTrailToCloudWatchLogging"
}

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_cloud_trail_to_cloud_watch_logging-attach" {
  role       = aws_iam_role.remediation_role_enable_cloud_trail_to_cloud_watch_logging.name
  policy_arn = aws_iam_policy.remediation_policy_enable_cloud_trail_to_cloud_watch_logging.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_cloud_trail_to_cloud_watch_logging-attach" {
  role       = aws_iam_role.remediation_role_enable_cloud_trail_to_cloud_watch_logging.name
  policy_arn = aws_iam_policy.remediation_role_enable_cloud_trail_to_cloud_watch_logging.arn
}

##RZ-EnableAWSConfig
resource "aws_iam_policy" "remediation_policy_enable_aws_config" {
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
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":sns:*:", data.aws_caller_identity.current.account_id, ":RZ--AWSConfigNotification"])
      },
      {
        Action   = "ssm:StartAutomationExecution"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/RZ-CreateAccessLoggingBucket:*"])
      },
      {
        Action = [
          "ssm:GetAutomationExecution",
          "config:PutConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:DescribeConfigurationRecorders",
          "config:StartConfigurationRecorder"
        ]
        Effect   = "Allow"
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
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":s3:::RZ-*"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableAWSConfig"
}

resource "aws_iam_policy" "remediation_role_enable_aws_config" {
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
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableAWSConfig"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableAWSConfig"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*::automation-definition/*"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-execution/*"])
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableAWSConfig"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableAWSConfig"
}

resource "aws_iam_role" "remediation_role_enable_aws_config" {
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
  name = "RZ-EnableAWSConfig"
}

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_aws_config-attach" {
  role       = aws_iam_role.remediation_role_enable_aws_config.name
  policy_arn = aws_iam_policy.remediation_policy_enable_aws_config.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_aws_config-attach" {
  role       = aws_iam_role.remediation_role_enable_aws_config.name
  policy_arn = aws_iam_policy.remediation_role_enable_aws_config.arn
}

##RZ-ConfigureS3BucketLogging
resource "aws_iam_policy" "remediation_policy_configure_s3_bucket_logging" {
  policy = {
    Statement = [
      {
        Action = [
          "s3:PutBucketLogging",
          "s3:CreateBucket",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketAcl"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyConfigureS3BucketLogging"
}

resource "aws_iam_policy" "remediation_role_configure_s3_bucket_logging" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-ConfigureS3BucketLogging"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleConfigureS3BucketLogging"
}

resource "aws_iam_role" "remediation_role_configure_s3_bucket_logging" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_configure_s3_bucket_logging-attach" {
  role       = aws_iam_role.remediation_role_configure_s3_bucket_logging.name
  policy_arn = aws_iam_policy.remediation_policy_configure_s3_bucket_logging.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_configure_s3_bucket_logging-attach" {
  role       = aws_iam_role.remediation_role_configure_s3_bucket_logging.name
  policy_arn = aws_iam_policy.remediation_role_configure_s3_bucket_logging.arn
}

##RZ-EnableCloudTrailEncryption
resource "aws_iam_policy" "remediation_policy_enable_cloud_trail_encryption" {
  policy = {
    Statement = [
      {
        Action   = "cloudtrail:UpdateTrail"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableCloudTrailEncryption"
}

resource "aws_iam_policy" "remediation_role_enable_cloud_trail_encryption" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableCloudTrailEncryption"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableCloudTrailEncryption"
}

resource "aws_iam_role" "remediation_role_enable_cloud_trail_encryption" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_cloud_trail_encryption-attach" {
  role       = aws_iam_role.remediation_role_enable_cloud_trail_encryption.name
  policy_arn = aws_iam_policy.remediation_policy_enable_cloud_trail_encryption.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_cloud_trail_encryption-attach" {
  role       = aws_iam_role.remediation_role_enable_cloud_trail_encryption.name
  policy_arn = aws_iam_policy.remediation_role_enable_cloud_trail_encryption.arn
}

##RZ-EnableKeyRotation
resource "aws_iam_policy" "remediation_policy_enable_key_rotation" {
  policy = {
    Statement = [
      {
        Action = [
          "kms:EnableKeyRotation",
          "kms:GetKeyRotationStatus"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableKeyRotation"
}

resource "aws_iam_policy" "remediation_role_enable_key_rotation" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableKeyRotation"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableKeyRotation"
}

resource "aws_iam_role" "remediation_role_enable_key_rotation" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_key_rotation-attach" {
  role       = aws_iam_role.remediation_role_enable_key_rotation.name
  policy_arn = aws_iam_policy.remediation_policy_enable_key_rotation.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_key_rotation-attach" {
  role       = aws_iam_role.remediation_role_enable_key_rotation.name
  policy_arn = aws_iam_policy.remediation_role_enable_key_rotation.arn
}

##RZ-EnableVPCFlowLogs
resource "aws_iam_policy" "remediation_policy_enable_vpc_flow_logs" {
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
        Action   = "iam:PassRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableVPCFlowLogs-remediationRole"])
      },
      {
        Action   = "ssm:GetParameter"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":parameter/RZ/CMK_REMEDIATION_ARN"])
      },
      {
        Action = [
          "ec2:DescribeFlowLogs",
          "logs:CreateLogGroup",
          "logs:DescribeLogGroups"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyEnableVPCFlowLogs"
}

resource "aws_iam_role" "enable_vpc_flow_logsremediationrole" {
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
            Effect   = "Allow"
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

resource "aws_iam_policy" "remediation_role_enable_vpc_flow_logs" {
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
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableVPCFlowLogs"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-EnableVPCFlowLogs"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"])
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-EnableVPCFlowLogs"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleEnableVPCFlowLogs"
}

resource "aws_iam_role" "remediation_role_enable_vpc_flow_logs" {
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
  name = "RZ-EnableVPCFlowLogs"
}

resource "aws_iam_role_policy_attachment" "remediation_policy_enable_vpc_flow_logs-attach" {
  role       = aws_iam_role.remediation_role_enable_vpc_flow_logs.name
  policy_arn = aws_iam_policy.remediation_policy_enable_vpc_flow_logs.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_enable_vpc_flow_logs-attach" {
  role       = aws_iam_role.remediation_role_enable_vpc_flow_logs.name
  policy_arn = aws_iam_policy.remediation_role_enable_vpc_flow_logs.arn
}

##RZ-CreateLogMetricFilterAndAlarm
resource "aws_iam_policy" "remediation_policy_create_log_metric_filter_and_alarm" {
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
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":sns:*:", data.aws_caller_identity.current.account_id, ":RZ--LocalAlarmNotification"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyCreateLogMetricFilterAndAlarm"
}

resource "aws_iam_policy" "remediation_role_create_log_metric_filter_and_alarm" {
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
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-CreateLogMetricFilterAndAlarm"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleCreateLogMetricFilterAndAlarm"
}

resource "aws_iam_role" "remediation_role_create_log_metric_filter_and_alarm" {
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

resource "aws_iam_role_policy_attachment" "remediation_policy_create_log_metric_filter_and_alarm-attach" {
  role       = aws_iam_role.remediation_role_create_log_metric_filter_and_alarm.name
  policy_arn = aws_iam_policy.remediation_policy_create_log_metric_filter_and_alarm.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_create_log_metric_filter_and_alarm-attach" {
  role       = aws_iam_role.remediation_role_create_log_metric_filter_and_alarm.name
  policy_arn = aws_iam_policy.remediation_role_create_log_metric_filter_and_alarm.arn
}

##RZ-RemoveVPCDefaultSecurityGroupRules
resource "aws_iam_policy" "remediation_policy_remove_vpc_default_security_group_rules" {
  policy = {
    Statement = [
      {
        Action = [
          "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":ec2:*:", data.aws_caller_identity.current.account_id, ":security-group/*"])
      },
      {
        Action = [
          "ec2:DescribeSecurityGroupReferences",
          "ec2:DescribeSecurityGroups"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationPolicyRemoveVPCDefaultSecurityGroupRules"
}

resource "aws_iam_policy" "remediation_role_remove_vpc_default_security_group_rules" {
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
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RemoveVPCDefaultSecurityGroupRules"])
      },
      {
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution",
          "ssm:DescribeAutomationStepExecutions"
        ]
        Effect = "Allow"
        Resource = [
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":document/RZ-RemoveVPCDefaultSecurityGroupRules"]),
          join("", ["arn:", data.aws_partition.current.partition, ":ssm:*:", data.aws_caller_identity.current.account_id, ":automation-definition/*"]),
        ]
      },
      {
        Action   = "sts:AssumeRole"
        Effect   = "Allow"
        Resource = join("", ["arn:", data.aws_partition.current.partition, ":iam::", data.aws_caller_identity.current.account_id, ":role/RZ-RemoveVPCDefaultSecurityGroupRules"])
      }
    ]
    Version = "2012-10-17"
  }
  name = "RemediationRoleRemoveVPCDefaultSecurityGroupRules"
}

resource "aws_iam_role" "remediation_role_remove_vpc_default_security_group_rules" {
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
  name = "RZ-RemoveVPCDefaultSecurityGroupRules"
}

resource "aws_iam_role_policy_attachment" "remediation_policy_remove_vpc_default_security_group_rules-attach" {
  role       = aws_iam_role.remediation_role_remove_vpc_default_security_group_rules.name
  policy_arn = aws_iam_policy.remediation_policy_remove_vpc_default_security_group_rules.arn
}

resource "aws_iam_role_policy_attachment" "remediation_role_remove_vpc_default_security_group_rules-attach" {
  role       = aws_iam_role.remediation_role_remove_vpc_default_security_group_rules.name
  policy_arn = aws_iam_policy.remediation_role_remove_vpc_default_security_group_rules.arn
}
