
module "encryption_default_ebs" {
  source = "./modules/ebs_encryption"
}

module "active_password_policy" {
  source = "./modules/active_password_policy"
}

module "create_scp" {
  source = "./modules/create_scp"
}
output "scp_id" {
  value = module.create_scp.scp_id
}

module "attach_scp" {
  source    = "./modules/attach_scp"
  scp_id    = module.create_scp.scp_id
  target_id = module.create_ou.target_id

}

module "create_ou" {
  source = "./modules/create_ou"
}



