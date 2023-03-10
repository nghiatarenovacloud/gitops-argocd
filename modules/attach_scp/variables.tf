variable "scp_id" {
  type        = list(string)
  description = "id of service control policy"
}

variable "target_id" {
  type        = string
  description = "target id of service that SCP attached"

}
