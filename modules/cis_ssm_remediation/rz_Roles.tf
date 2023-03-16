data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

variable "sec_hub_admin_account" {
  description = "Admin account number"
  type        = string
}
#RZ-SetIAMPasswordPolicy
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
