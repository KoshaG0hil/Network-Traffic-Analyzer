output "vpc_flow_logs_bucket" {
  value       = aws_s3_bucket.vpc_flow_logs.bucket
  description = "S3 Bucket storing raw VPC Flow Logs"
}

output "athena_results_bucket" {
  value       = aws_s3_bucket.athena_results.bucket
  description = "S3 Bucket storing Athena query results"
}

output "athena_database" {
  value       = aws_athena_database.vpc_flow_db.name
  description = "Athena Database for VPC Flow Logs"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.network_alerts.arn
  description = "SNS Topic ARN for threat alerts"
}
