terraform {
  backend "s3" {
    bucket = "taduynghia-terraform-statefile"
    key    = "awsorg/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "this" {

}
