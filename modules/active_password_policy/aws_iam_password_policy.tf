resource "aws_iam_account_password_policy" "project" {
  minimum_password_length          = var.minimum_password_length
  require_lowercase_characters     = var.require_lowercase_characters
  require_uppercase_characters     = var.require_uppercase_characters
  require_numbers                  = var.require_numbers
  require_symbols                  = var.require_symbols
  allow_users_to_change_password   = var.allow_users_to_change_password
#   max_password_age                 = var.max_password_age
#   password_reuse_prevention        = var.password_reuse_prevention
#   hard_expiry                      = var.hard_expiry
}