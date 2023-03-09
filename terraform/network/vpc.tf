locals {
  vpc_prefix         = "renozone-default"
  tgw_ram_principals = []
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "ingress" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.19.0"

  name = "${vpc_prefix}-ingress"
  cidr = "10.101.0.0/16"

  azs             = data.aws_availability_zones.available.zone_ids
  private_subnets = ["10.101.1.0/24", "10.101.2.0/24", "10.101.3.0/24"]
  public_subnets  = ["10.101.101.0/24", "10.101.102.0/24", "10.101.103.0/24"]

  tags = {}
}

module "egress" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.19.0"

  name = "${vpc_prefix}-egress"
  cidr = "10.102.0.0/16"

  azs             = data.aws_availability_zones.available.zone_ids
  private_subnets = ["10.102.1.0/24", "10.102.2.0/24", "10.102.3.0/24"]
  public_subnets  = ["10.102.101.0/24", "10.102.102.0/24", "10.102.103.0/24"]

  tags = {}
}

module "inspection" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.19.0"

  name = "${vpc_prefix}-inspection"
  cidr = "10.103.0.0/16"

  azs             = data.aws_availability_zones.available.zone_ids
  private_subnets = ["10.103.1.0/24", "10.103.2.0/24", "10.103.3.0/24"]
  public_subnets  = ["10.103.101.0/24", "10.103.102.0/24", "10.103.103.0/24"]

  tags = {}
}

module "shared" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.19.0"

  name = "${vpc_prefix}-shared"
  cidr = "10.104.0.0/16"

  azs             = data.aws_availability_zones.available.zone_ids
  private_subnets = ["10.104.1.0/24", "10.104.2.0/24", "10.104.3.0/24"]
  public_subnets  = ["10.104.101.0/24", "10.104.102.0/24", "10.104.103.0/24"]

  tags = {}
}

module "tgw" {
  source  = "terraform-aws-modules/transit-gateway/aws"
  version = "2.9.0"

  name        = "my-tgw"
  description = "My TGW shared with several other AWS accounts"

  enable_auto_accept_shared_attachments = true

  vpc_attachments = {
    ingress = {
      vpc_id      = module.ingress.vpc_id
      subnet_ids  = module.ingress.private_subnets
      dns_support = true

      tgw_routes = []
    }
    egress = {
      vpc_id      = module.egress.vpc_id
      subnet_ids  = module.egress.private_subnets
      dns_support = true

      tgw_routes = []
    }
    inspection = {
      vpc_id      = module.inspection.vpc_id
      subnet_ids  = module.inspection.private_subnets
      dns_support = true

      tgw_routes = []
    }
    shared = {
      vpc_id      = module.shared.vpc_id
      subnet_ids  = module.shared.private_subnets
      dns_support = true

      tgw_routes = []
    }
  }

  ram_allow_external_principals = true
  ram_principals                = local.tgw_ram_principals

  tags = {}
}
