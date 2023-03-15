resource "aws_guardduty_detector" "this" {
  enable = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency
}

# Only apply below resources after configured delegated admin at Master account
## Auto enable guardduty in organization member accounts
resource "aws_guardduty_organization_configuration" "delegated_admin" {
  auto_enable = true
  detector_id = aws_guardduty_detector.this[0].id
  
  datasources {
    s3_logs {
      enable = var.guardduty_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.guardduty_eks_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.guardduty_malware_protection
        }
      }
    }
  }
}

resource "aws_guardduty_publishing_destination" "export" {
  detector_id     = aws_guardduty_detector.this[0].id
  destination_arn = var.guardduty_findings_export.s3_arn
  kms_key_arn     = var.guardduty_findings_export.kms_arn
}
