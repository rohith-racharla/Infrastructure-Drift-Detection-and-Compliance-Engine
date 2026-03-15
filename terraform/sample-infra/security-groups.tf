# =======================================
# Sample Infrastructure - Security Groups
# =======================================

# Security groups for the sample infrastructure. These are prime candidates
# for drift detection; Engineers often modify SG rules via the AWS Console
# during incidents and forget to update Terraform.

# -------------------------
# Web Server Security Group
# -------------------------

resource "aws_security_group" "web_server" {
  name        = "${var.project_name}-${var.environment}-web-server-sg"
  description = "Security group for the web server instance"
  vpc_id      = aws_vpc.main.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-web-server-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Inbound: Allow HTTP (port 80) from anywhere
resource "aws_vpc_security_group_ingress_rule" "web_http" {
  security_group_id = aws_security_group.web_server.id
  description       = "Allow HTTP traffic from the internet"

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-http-ingress"
  })
}

# Inbound: Allow HTTPS (port 443) from anywhere
resource "aws_vpc_security_group_ingress_rule" "web_https" {
  security_group_id = aws_security_group.web_server.id
  description       = "Allow HTTPS traffic from the internet"

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-https-ingress"
  })
}

# Inbound: Allow SSH (port 22) from specified CIDRs
resource "aws_vpc_security_group_ingress_rule" "web_ssh" {
  security_group_id = aws_security_group.web_server.id
  description       = "Allow SSH access from ${var.allowed_ssh_cidrs}"

  cidr_ipv4   = var.allowed_ssh_cidrs
  from_port   = 22
  to_port     = 22
  ip_protocol = "tcp"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-ssh-ingress"
  })
}

# Outbound: Allow all traffic
resource "aws_vpc_security_group_egress_rule" "web_all_outbound" {
  security_group_id = aws_security_group.web_server.id
  description       = "Allow all outbound traffic"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-all-egress"
  })
}

# ----------------------------------------------
# Database Security Group (internal access only)
# ----------------------------------------------

resource "aws_security_group" "database" {
  name        = "${var.project_name}-${var.environment}-database-sg"
  description = "Security group for database instances (internal only)"
  vpc_id      = aws_vpc.main.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-database-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Inbound: Allow MySQL/Aurora (port 3306) from the web server SG only
resource "aws_vpc_security_group_ingress_rule" "db_mysql" {
  security_group_id = aws_security_group.database.id
  description       = "Allow MySQL connections from web server"

  referenced_security_group_id = aws_security_group.web_server.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-mysql-ingress"
  })
}

# Inbound: Allow PostgreSQL (port 5432) from the web server SG only
resource "aws_vpc_security_group_ingress_rule" "db_postgres" {
  security_group_id = aws_security_group.database.id
  description       = "Allow PostgreSQL connections from web server"

  referenced_security_group_id = aws_security_group.web_server.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-postgres-ingress"
  })
}

# Outbound: Allow all traffic (for updates, etc.)
resource "aws_vpc_security_group_egress_rule" "db_all_outbound" {
  security_group_id = aws_security_group.database.id
  description       = "Allow all outbound traffic"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1" # Semantically equivalent to all ports

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-db-all-egress"
  })
}
