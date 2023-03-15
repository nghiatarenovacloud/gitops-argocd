variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "guardduty_finding_publishing_frequency" {
  type = string
  description = "(optional) describe your variable"
  default = "SIX_HOURS"
}

variable "guardduty_s3_protection" {
  type = bool
  description = "Enable S3 Protection automatically for new member accounts"
  default = false
}

variable "guardduty_eks_protection" {
  type = bool
  description = "Enable Kubernetes Audit Logs Monitoring automatically for new member accounts"
  default = false
}

variable "guardduty_malware_protection" {
  type = bool
  description = "Enable Malware Protection (related to an EC2 instance or container workload) automatically for new member accounts"
  default = false
}

variable "guardduty_findings_export" {
  description = "(optional) describe your variable"
}
