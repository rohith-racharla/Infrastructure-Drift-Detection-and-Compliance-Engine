# =======================================
# Sample Infrastructure - Input Variables
# =======================================

variable "aws_region" {
  description = "AWS region to deploy the sample infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "sample-infra"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

variable "instance_type" {
  description = "EC2 instance type (free-tier: t3.micro)"
  type        = string
  default     = "t3.micro"
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH into the EC2 instance. No default; must be explicitly set."
  type        = string
  # No default provided; forces the user to consciously restrict SSH access.
  # Example: ["203.0.113.0/32"] for a single IP, or ["10.0.0.0/8"] for internal.
}

variable "enable_nat_gateway" {
  description = "Whether to create a NAT Gateway (costs money; disable for free-tier)"
  type        = bool
  default     = false
}

variable "common_tags" {
  description = "Additional tags applied to all resources"
  type        = map(string)
  default = {
    Owner      = "devops-team"
    CostCenter = "engineering"
  }
}
