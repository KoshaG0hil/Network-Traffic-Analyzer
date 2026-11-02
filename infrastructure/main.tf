terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- S3 Bucket for Raw VPC Flow Logs ---
resource "aws_s3_bucket" "vpc_flow_logs" {
  bucket        = "vpc-flow-logs-${var.environment}-${var.aws_account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vpc_flow_logs" {
  bucket = aws_s3_bucket.vpc_flow_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "vpc_flow_logs" {
  bucket                  = aws_s3_bucket.vpc_flow_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- S3 Bucket for Athena Query Results ---
resource "aws_s3_bucket" "athena_results" {
  bucket        = "athena-query-results-${var.environment}-${var.aws_account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Athena Database & Workgroup ---
resource "aws_athena_database" "vpc_flow_db" {
  name   = "vpc_flow_logs_db"
  bucket = aws_s3_bucket.athena_results.id
}

resource "aws_athena_workgroup" "security_analytics" {
  name = "vpc-security-analytics"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/output/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

# --- SNS Topic for Threat Alerts ---
resource "aws_sns_topic" "network_alerts" {
  name = "vpc-network-anomaly-alerts"
}

# --- IAM Role for Lambda Anomaly Scanner ---
resource "aws_iam_role" "lambda_anomaly_scanner" {
  name = "lambda-vpc-anomaly-scanner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-athena-sns-policy"
  role = aws_iam_role.lambda_anomaly_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.vpc_flow_logs.arn,
          "${aws_s3_bucket.vpc_flow_logs.arn}/*",
          aws_s3_bucket.athena_results.arn,
          "${aws_s3_bucket.athena_results.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.network_alerts.arn
      }
    ]
  })
}
