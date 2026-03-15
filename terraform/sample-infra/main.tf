# ==========================================
# Sample Infrastructure - Main Configuration
# ==========================================

# This Terraform configuration deploys a realistic small AWS environment
# intended to be monitored for infrastructure drift. It provisions a VPC with
# public/private subnets, an EC2 instance, security groups, and IAM resources.


terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Use local backend for demo purposes.
  # In production, switch to S3 backend for remote state:
  #
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "sample-infra/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-state-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "Infrastructure-Drift-Detection-and-Compliance-Engine"
    }
  }
}

# ------------
# Data Sources
# ------------

# Fetch available AZs in the selected region
data "aws_availability_zones" "available" {
  state = "available"
}

# Fetch the latest Amazon Linux 2023 AMI (free-tier eligible)
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}
