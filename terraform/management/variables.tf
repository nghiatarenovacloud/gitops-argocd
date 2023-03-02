variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "audit_account_id" {
  type        = string
  description = "AWS account ID of Audit account"
}
