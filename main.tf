module "encryption_default_ebs" {
  source = "./modules/ebs_encryption"
}

module "active_password_policy" {
  source = "./modules/active_password_policy"
}

module "create_scp" {
  source = "./modules/create_scp"
}

module "attach_scp" {
  source    = "./modules/attach_scp"
  scp_id    = module.create_scp.scp_id
  target_id = module.create_ou.target_id
  depends_on = [
    module.create_ou
  ]
}

module "create_ou" {
  source = "./modules/create_ou"
}

# module "enable_service_organization" {
#   source = "./modules/enable_service_organization"
# }

