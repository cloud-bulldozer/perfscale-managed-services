# File initially loaded from https://gist.githubusercontent.com/wgordon17/d88501a15204a2f8143bc275a3f64c80/raw/setup-vpc.tf

variable "cluster_name" {
  type        = string
  description = "The name of the ROSA cluster to create"
  default     = "rosa-cluster"
}

variable "aws_region" {
  type        = string
  description = "The region to create the ROSA cluster in"
  default     = "us-east-2"
}

data "aws_availability_zones" "available" {
  state = "available"
}

provider "aws" {
  region = var.aws_region
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.14.2"
  azs     = [data.aws_availability_zones.available.names[0]]
  name    = "vpc-${var.cluster_name}"
  cidr    = "10.0.0.0/16"

  private_subnets = ["10.0.1.0/24"]
  public_subnets  = ["10.0.101.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true
}

output "vpc-id" {
  value = module.vpc.vpc_id
}

output "cluster-private-subnet" {
  value = module.vpc.private_subnets[0]
}

output "cluster-public-subnet" {
  value = module.vpc.public_subnets[0]
}
