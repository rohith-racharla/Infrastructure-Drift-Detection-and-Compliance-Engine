# =====================================
# Sample Infrastructure - IAM Resources
# =====================================

# IAM roles, policies, and instance profiles. IAM drift is classified as
# "critical" by the drift scanner since unauthorized IAM changes can create
# serious security gaps.

# ---------------------------
# EC2 Instance Profile & Role
# ---------------------------

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-${var.environment}-ec2-profile"
  role = aws_iam_role.ec2_role.name

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-ec2-profile"
  })
}

resource "aws_iam_role" "ec2_role" {
  name        = "${var.project_name}-${var.environment}-ec2-role"
  description = "IAM role for the web server EC2 instance"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-ec2-role"
  })
}

# Allow EC2 to read from S3 (e.g., pull config files)
resource "aws_iam_role_policy" "ec2_s3_read" {
  name = "${var.project_name}-${var.environment}-ec2-s3-read"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3Read"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-${var.environment}-*",
          "arn:aws:s3:::${var.project_name}-${var.environment}-*/*"
        ]
      }
    ]
  })
}

# Allow EC2 to write CloudWatch logs
resource "aws_iam_role_policy" "ec2_cloudwatch" {
  name = "${var.project_name}-${var.environment}-ec2-cloudwatch"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/ec2/${var.project_name}-${var.environment}*"
      }
    ]
  })
}

# Attach SSM managed policy for Systems Manager access (allows console-based access)
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
