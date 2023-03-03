variable "aws_region" {
  description = "vpc_project"
  type        = string
  default     = "us-west-1"
}
variable "organization_service" {
  type = list(string)
  default = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
  ]
}
