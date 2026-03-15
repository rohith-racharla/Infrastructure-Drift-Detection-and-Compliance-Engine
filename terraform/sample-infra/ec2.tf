# ====================================
# Sample Infrastructure - EC2 Instance
# ====================================

# Deploys a free-tier eligible t2.micro EC2 instance in the public subnet
# with proper tagging for drift detection demonstrations.

# ------------
# EC2 Instance
# ------------

resource "aws_instance" "web_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.web_server.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # Enable detailed monitoring (drift detection target)
  monitoring = false

  # Root volume configuration
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30 # minimum value
    encrypted             = true
    delete_on_termination = true

    tags = merge(var.common_tags, {
      Name = "${var.project_name}-${var.environment}-web-server-root"
    })
  }

  # Enable IMDSv2 (security best practice — CIS Benchmark)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    echo "<h1>Drift Detection and Compliance Engine: Sample Server</h1><p>Environment: ${var.environment}</p>" > /var/www/html/index.html
  EOF
  )

  tags = merge(var.common_tags, {
    Name        = "${var.project_name}-${var.environment}-web-server"
    Application = "web-server"
    Backup      = "daily"
  })

  lifecycle {
    # Prevent accidental destruction during demos
    prevent_destroy = false
  }
}

# Elastic IP for the web server (optional, but good for drift demo)
resource "aws_eip" "web_server" {
  instance = aws_instance.web_server.id
  domain   = "vpc"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-web-server-eip"
  })

  depends_on = [aws_internet_gateway.main]
}
