# ===============================
# Sample Infrastructure - Outputs
# ===============================

# These outputs are useful for the drift scanner to identify which resources
# to monitor, and for scripts to reference deployed resource IDs.

# ----------------
# VPC & Networking
# ----------------

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

output "nat_gateway_id" {
  description = "ID of the NAT Gateway (empty if disabled)"
  value       = var.enable_nat_gateway ? aws_nat_gateway.main[0].id : null
}

# ---
# EC2
# ---

output "web_server_instance_id" {
  description = "Instance ID of the web server"
  value       = aws_instance.web_server.id
}

output "web_server_public_ip" {
  description = "Elastic IP of the web server"
  value       = aws_eip.web_server.public_ip
}

output "web_server_private_ip" {
  description = "Private IP of the web server"
  value       = aws_instance.web_server.private_ip
}

# ---------------
# Security Groups
# ---------------

output "web_server_sg_id" {
  description = "Security Group ID for the web server"
  value       = aws_security_group.web_server.id
}

output "database_sg_id" {
  description = "Security Group ID for the database"
  value       = aws_security_group.database.id
}

# ---
# IAM
# ---

output "ec2_role_arn" {
  description = "ARN of the EC2 IAM role"
  value       = aws_iam_role.ec2_role.arn
}

output "ec2_instance_profile_arn" {
  description = "ARN of the EC2 instance profile"
  value       = aws_iam_instance_profile.ec2_profile.arn
}

# -------
# Summary
# -------

output "deployment_summary" {
  description = "Summary of deployed resources for quick reference"
  value = {
    region         = var.aws_region
    environment    = var.environment
    vpc_id         = aws_vpc.main.id
    web_server_ip  = aws_eip.web_server.public_ip
    web_server_url = "http://${aws_eip.web_server.public_ip}"
  }
}
